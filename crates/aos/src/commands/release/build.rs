//! Exact planned Nix realization, reproducibility checks, and build evidence.
//!
//! Every planned derivation is realized and then repeat-built with Nix
//! `--check`. The plan's registry tier decides what a failed check means:
//! production fails the step closed, while the testing tier records each
//! affected output as [`ReproducibilityResult::NotReproduced`] and continues.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_core::nix::{CheckReport, NixRunner};
use aos_core::output::Printer;
use aos_release::build::{
    BUILD_REPORT_V1, BuildOutputEvidence, BuildReportV1, BuildSourceEvidence,
    ReproducibilityResult, planned_nix_outputs,
};
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::plan::ReleasePlan;
use aos_release::platform::{MatrixCell, Platform};
use aos_release::registry::{RegistryTier, registry_policy};
use aos_release::sbom::SpdxDocument;
use aos_release::state::{JournalEntry, ReleaseState};
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
    let plan: ReleasePlan = canonical::from_slice(&plan_bytes, "release plan")?;
    plan.validate()?;
    super::artifact_profiles::require_plan(nix, &plan)?;
    let tier = registry_policy(&plan.registry)?.tier();
    let plan_digest = Sha256Digest::of_bytes(&plan_bytes);
    let planned = planned_nix_outputs(&plan)?;
    let derivations = planned
        .values()
        .map(|output| PathBuf::from(output.derivation))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    instantiate_planned_roots(nix, &plan, &derivations)?;

    printer.info(&format!(
        "Realizing {} exact outputs from {} derivations...",
        planned.len(),
        derivations.len()
    ));
    nix.realise_derivations(&derivations, false)?;
    printer.info("Repeat-building planned derivations with Nix --check...");
    let checks = nix.check_derivations(&derivations)?;
    let unreproduced = admit_check_failures(tier, &checks)?;
    warn_unreproduced(printer, tier, &unreproduced);

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
        require_equivalent_deriver(
            id,
            info.deriver.as_deref(),
            expected.derivation,
            expected.store_path,
            |derivation, binding| {
                nix.store_query(Path::new(derivation), &["--query", "--binding", binding])
            },
        )?;
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
            reproducibility: reproducibility_of(expected.derivation, &unreproduced),
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
        "not_reproduced": unreproduced,
        "output": args.output,
    })) {
        return Ok(());
    }
    let not_reproduced = report.not_reproduced().count();
    let summary = if not_reproduced == 0 {
        String::new()
    } else {
        format!(" ({not_reproduced} recorded as not reproduced)")
    };
    printer.success(&format!(
        "Built and repeat-checked {} planned outputs{summary}; evidence written to {}",
        report.outputs.len(),
        args.output.display()
    ));
    Ok(())
}

/// Requires a realized output's recorded deriver to be the planned one or
/// an equivalent derivation.
///
/// Nix records whichever derivation first produced a store path as its
/// deriver. Input-addressed derivations that differ only in fixed-output
/// inputs, such as a source fetch with a different URL list but the same
/// hash, produce the same output paths. A different recorded deriver is
/// accepted only when it is a store derivation whose output of the same
/// name produces exactly the planned store path. The evidence still names
/// the planned derivation.
///
/// The plan names a package alias of a non-default output by the logical
/// output `out`, so the Nix output name is found on the planned derivation:
/// it is the output that produces the planned store path.
///
/// `binding` returns a derivation's environment binding: the
/// whitespace-separated output names for `outputs`, and an output's store
/// path for that output's name.
///
/// # Errors
///
/// Returns an error when no deriver is recorded, when the recorded deriver
/// is not a store derivation, when a binding cannot be read, when no output
/// of the planned derivation produces the planned store path, or when the
/// recorded deriver's output of that name produces a different path.
fn require_equivalent_deriver(
    id: &str,
    recorded: Option<&str>,
    planned: &str,
    store_path: &str,
    binding: impl Fn(&str, &str) -> Result<String>,
) -> Result<()> {
    let Some(recorded) = recorded else {
        bail!("realized output {id} has no recorded deriver");
    };
    if recorded == planned {
        return Ok(());
    }
    if !recorded.starts_with("/nix/store/") || !recorded.ends_with(".drv") {
        bail!("realized output {id} names a deriver outside the Nix store: {recorded}");
    }

    let output = planned_output_name(id, planned, store_path, &binding)?;
    let bound = binding(recorded, &output).with_context(|| {
        format!("reading output {output} of {id}'s recorded deriver {recorded}")
    })?;
    if bound.trim() != store_path {
        bail!("realized output {id} has a different deriver than the plan");
    }
    Ok(())
}

/// Returns the Nix output of the planned derivation that produces `store_path`.
fn planned_output_name(
    id: &str,
    planned: &str,
    store_path: &str,
    binding: &impl Fn(&str, &str) -> Result<String>,
) -> Result<String> {
    let names = binding(planned, "outputs")
        .with_context(|| format!("reading the outputs of {id}'s planned derivation"))?;
    for name in names.split_whitespace() {
        let path = binding(planned, name)
            .with_context(|| format!("reading output {name} of {id}'s planned derivation"))?;
        if path.trim() == store_path {
            return Ok(name.to_string());
        }
    }
    bail!("no output of {id}'s planned derivation produces {store_path}")
}

/// Decides which failed repeat builds the plan's registry tier admits.
///
/// Returns each derivation to record as not reproduced, keyed by store path,
/// with the one-line reason its check failed. A tier that does not accept
/// unreproduced outputs fails closed with the full failure report, exactly
/// as the check pass did before tiers could record them.
///
/// # Errors
///
/// Returns the check pass's [`aos_core::error::AosError::NixBuild`] report
/// when any derivation failed its check and `tier` does not accept
/// unreproduced outputs.
fn admit_check_failures(
    tier: RegistryTier,
    checks: &CheckReport,
) -> Result<BTreeMap<String, String>> {
    if !tier.accepts_not_reproduced_outputs() {
        checks.require_all_reproduced()?;
    }

    let unreproduced = checks
        .failures()
        .iter()
        .map(|failure| (failure.derivation.display().to_string(), failure.reason()))
        .collect();
    Ok(unreproduced)
}

/// Returns the recorded repeat-build result for an output's derivation.
fn reproducibility_of(
    derivation: &str,
    unreproduced: &BTreeMap<String, String>,
) -> ReproducibilityResult {
    if unreproduced.contains_key(derivation) {
        ReproducibilityResult::NotReproduced
    } else {
        ReproducibilityResult::Reproduced
    }
}

/// Lists every derivation the release records as not reproduced.
fn warn_unreproduced(
    printer: &Printer,
    tier: RegistryTier,
    unreproduced: &BTreeMap<String, String>,
) {
    if unreproduced.is_empty() {
        return;
    }

    printer.warning(&format!(
        "{} derivations did not reproduce under Nix --check; the {tier} registry tier \
         records their outputs as not-reproduced and the release proceeds:",
        unreproduced.len()
    ));
    for (derivation, reason) in unreproduced {
        printer.warning(&format!("  {derivation}: {reason}"));
    }
}

fn instantiate_planned_roots(
    nix: &NixRunner,
    plan: &ReleasePlan,
    planned_derivations: &[PathBuf],
) -> Result<()> {
    let mut instantiated = BTreeSet::new();
    for platform in Platform::ALL {
        instantiated.extend(
            nix.instantiate_all_for_target("releasePackageDerivationRoots", platform.as_str())?,
        );
    }

    for image in &plan.images {
        let attribute = format!(
            "systems.{}.config.system.build.unsignedImageAssembly",
            image.system_variant
        );
        for cell in &image.platforms {
            if !matches!(cell.decision, MatrixCell::Artifact { .. }) {
                continue;
            }
            instantiated.insert(nix.instantiate_for_target(&attribute, cell.platform.as_str())?);
        }
    }

    let missing = planned_derivations
        .iter()
        .filter(|derivation| !instantiated.contains(*derivation))
        .map(|derivation| derivation.display().to_string())
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!(
            "current source did not instantiate planned derivations: {}",
            missing.join(", ")
        );
    }

    Ok(())
}

fn build_journal(
    plan_digest: Sha256Digest,
    started_at: &str,
    completed_at: &str,
    report: &[u8],
    sbom: &[u8],
) -> Result<Vec<u8>> {
    let planned = JournalEntry {
        schema_version: aos_release::RELEASE_JOURNAL_ENTRY.to_string(),
        sequence: 1,
        previous_entry_digest: None,
        plan_digest,
        manifest_digest: None,
        prior_state: None,
        new_state: ReleaseState::Planned,
        destination: None,
        operation_ids: vec!["release-plan".to_string()],
        evidence: vec![],
        recorded_at: started_at.to_string(),
    };
    planned.validate()?;
    let planned_digest = planned.digest()?;
    let built = JournalEntry {
        schema_version: aos_release::RELEASE_JOURNAL_ENTRY.to_string(),
        sequence: 2,
        previous_entry_digest: Some(planned_digest),
        plan_digest,
        manifest_digest: None,
        prior_state: Some(ReleaseState::Planned),
        new_state: ReleaseState::Built,
        destination: None,
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
    use aos_core::nix::CheckFailure;

    use super::*;

    const PLANNED_DRV: &str = "/nix/store/k7gj3crbgracfq1wnn39g7jsc87df0jz-glibc-2.39.drv";
    const EQUIVALENT_DRV: &str = "/nix/store/1sfvcsz3kqc7a4xfy114x3yycsa61rxv-glibc-2.39.drv";
    const MAIN_PATH: &str = "/nix/store/49br0y2s9c52ln7bxph87faa3kdkiyfz-glibc-2.39";
    const GETENT_PATH: &str = "/nix/store/l8l50qx80k70lclql35krjs6kris01pb-glibc-2.39-getent";

    /// Binds the planned and equivalent derivations' `out` and `getent`
    /// outputs, with the recorded deriver's `getent` set to `getent`.
    fn bindings(getent: &'static str) -> impl Fn(&str, &str) -> Result<String> {
        move |derivation, binding| match (derivation, binding) {
            (_, "outputs") => Ok("out getent\n".to_string()),
            (_, "out") => Ok(format!("{MAIN_PATH}\n")),
            (PLANNED_DRV, "getent") => Ok(format!("{GETENT_PATH}\n")),
            (EQUIVALENT_DRV, "getent") => Ok(format!("{getent}\n")),
            _ => bail!("unexpected binding {binding} of {derivation}"),
        }
    }

    #[test]
    fn planned_deriver_is_accepted_without_a_lookup() -> Result<()> {
        require_equivalent_deriver("id", Some(PLANNED_DRV), PLANNED_DRV, GETENT_PATH, |_, _| {
            bail!("the planned deriver needs no lookup")
        })
    }

    #[test]
    fn equivalent_deriver_producing_the_planned_output_is_accepted() -> Result<()> {
        require_equivalent_deriver(
            "id",
            Some(EQUIVALENT_DRV),
            PLANNED_DRV,
            GETENT_PATH,
            bindings(GETENT_PATH),
        )
    }

    #[test]
    fn equivalence_uses_the_nix_output_not_the_logical_out_name() {
        // The recorded deriver's `out` is the shared main path, so a check on
        // the logical name would compare the wrong output.
        let result = require_equivalent_deriver(
            "id",
            Some(EQUIVALENT_DRV),
            PLANNED_DRV,
            GETENT_PATH,
            bindings("/nix/store/hsjw5riiksy5w04rc4413asvr5c4k9h7-glibc-2.39-getent"),
        );

        assert!(result.is_err_and(|error| error.to_string().contains("different deriver")));
    }

    #[test]
    fn planned_derivation_must_produce_the_planned_path() {
        let result = require_equivalent_deriver(
            "id",
            Some(EQUIVALENT_DRV),
            PLANNED_DRV,
            "/nix/store/mlpmyg9jpridbzyjk4327mzw7hj175j2-other",
            bindings(GETENT_PATH),
        );

        assert!(result.is_err_and(|error| error.to_string().contains("no output")));
    }

    #[test]
    fn missing_or_foreign_derivers_are_rejected() {
        let missing =
            require_equivalent_deriver("id", None, PLANNED_DRV, GETENT_PATH, bindings(GETENT_PATH));
        let foreign = require_equivalent_deriver(
            "id",
            Some("/tmp/glibc-2.39.drv"),
            PLANNED_DRV,
            GETENT_PATH,
            bindings(GETENT_PATH),
        );

        assert!(missing.is_err());
        assert!(foreign.is_err());
    }

    #[test]
    fn unreadable_bindings_fail_closed() {
        let result = require_equivalent_deriver(
            "id",
            Some(EQUIVALENT_DRV),
            PLANNED_DRV,
            GETENT_PATH,
            |_, _| bail!("derivation is not valid"),
        );

        assert!(result.is_err());
    }

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
            .collect::<Result<Vec<JournalEntry>>>()?;

        assert_eq!(lines.len(), 2);
        assert_eq!(
            aos_release::verify::verify_journal(&lines)?.global,
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

    fn failed_check(derivation: &str, exit_code: i32, detail: &str) -> CheckFailure {
        CheckFailure {
            derivation: PathBuf::from(derivation),
            exit_code: Some(exit_code),
            detail: detail.to_owned(),
        }
    }

    fn mixed_check_pass() -> CheckReport {
        CheckReport::new(
            3,
            vec![
                failed_check(
                    "/nix/store/a-nondeterministic.drv",
                    104,
                    "error: derivation '/nix/store/a-nondeterministic.drv' may not be deterministic",
                ),
                failed_check(
                    "/nix/store/b-overloaded.drv",
                    100,
                    "building...\nerror: builder for '/nix/store/b-overloaded.drv' failed",
                ),
            ],
        )
    }

    #[test]
    fn testing_tier_records_failed_checks_against_their_outputs() -> Result<()> {
        let unreproduced = admit_check_failures(RegistryTier::Testing, &mixed_check_pass())?;

        assert_eq!(
            unreproduced
                .get("/nix/store/a-nondeterministic.drv")
                .map(String::as_str),
            Some("error: derivation '/nix/store/a-nondeterministic.drv' may not be deterministic")
        );
        assert_eq!(
            unreproduced
                .get("/nix/store/b-overloaded.drv")
                .map(String::as_str),
            Some("error: builder for '/nix/store/b-overloaded.drv' failed")
        );

        // Every output of a failed derivation is unreproduced; others are not.
        assert_eq!(
            reproducibility_of("/nix/store/a-nondeterministic.drv", &unreproduced),
            ReproducibilityResult::NotReproduced
        );
        assert_eq!(
            reproducibility_of("/nix/store/b-overloaded.drv", &unreproduced),
            ReproducibilityResult::NotReproduced
        );
        assert_eq!(
            reproducibility_of("/nix/store/c-reproduced.drv", &unreproduced),
            ReproducibilityResult::Reproduced
        );
        Ok(())
    }

    #[test]
    fn production_tier_fails_closed_on_any_failed_check() {
        let error = admit_check_failures(RegistryTier::Production, &mixed_check_pass())
            .expect_err("production must not record unreproduced outputs");

        let Some(aos_core::error::AosError::NixBuild { exit_code, stderr }) =
            error.downcast_ref::<aos_core::error::AosError>()
        else {
            panic!("expected the check pass's Nix build report, got {error:#}");
        };
        assert_eq!(*exit_code, 104);
        assert!(stderr.contains("/nix/store/a-nondeterministic.drv (exit code 104)"));
        assert!(stderr.contains("/nix/store/b-overloaded.drv (exit code 100)"));
    }

    #[test]
    fn every_tier_admits_a_fully_reproduced_check_pass() -> Result<()> {
        let clean = CheckReport::new(3, vec![]);

        for tier in [RegistryTier::Production, RegistryTier::Testing] {
            let unreproduced = admit_check_failures(tier, &clean)?;
            assert!(unreproduced.is_empty());
            assert_eq!(
                reproducibility_of("/nix/store/a-x.drv", &unreproduced),
                ReproducibilityResult::Reproduced
            );
        }
        Ok(())
    }

    #[test]
    fn timestamps_must_be_real_utc_rfc3339_values() {
        assert!(require_utc_time("2026-09-03T00:00:00Z", "time").is_ok());
        assert!(require_utc_time("2026-99-99T00:00:00Z", "time").is_err());
        assert!(require_utc_time("2026-09-03T00:00:00+01:00", "time").is_err());
    }
}
