//! `aos release fitness run <kind>` and `aos release fitness status`.
//!
//! Fitness attestations are maintainer-wide: one store under the
//! configuration's `fitness_root` (`<kind>/<performed_at>.json`) serves every
//! release of the registry while each attestation is fresh and its bindings
//! match the live values. `run` turns an exercise report into a signed
//! attestation:
//!
//! ```json
//! {"schema_version":"aos.release.fitness-report/v1",
//!  "performed_at":"2026-09-14T09:00:00Z",
//!  "checks":{"isolated-hub-restore":{"passed":true,"detail":"restored 1.2M objects"}},
//!  "operator":"oncall"}
//! ```
//!
//! Live binding values come from the configuration: `signer-roster` from
//! `[signer.roles]` (the roster `new` freezes into plans), `surface` and
//! `hub-schema` from `[surfaces.production]` (a Hub's deployment identity is
//! also probed live), `tooling` from the detected
//! [tooling environment](super::super::tooling), and `alert-config` from
//! `[alert]`.
//!
//! Neither command needs a frozen plan. Fitness kinds and profiles come from
//! the newest release plan under `work_root` when one exists, else from that
//! work directory's exported `contract.json`, else from the repository's Nix
//! contract export (the `step contract` leaf). Attestations are verified
//! against the configured `[signer.roles.release-evidence]` roster, falling
//! back to the newest plan's frozen roster.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context as _, Result, bail};
use aos_core::nix::NixRunner;
use aos_core::output::Printer;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::fitness::{FitnessAttestation, FitnessReport, LiveBindings};
use aos_release::plan::{PlannedDestination, ReleasePlan, SurfaceKind, SurfaceRole};
use aos_release::qualification::{FitnessKind, QualificationContract};
use aos_release::signing::{SignerRole, TrustedEd25519Key};

use super::super::capture;
use super::super::config::{MaintainerConfig, RoleKey};
use super::super::surface::readback;
use super::evidence::{self, EvidenceScope};
use super::keys;
use super::workdir::{self, WorkDir};
use crate::cli::{ReleaseFitnessRunArgs, ReleaseFitnessStatusArgs};

/// Bound on an exercise report read from a file or standard input.
const MAX_REPORT_BYTES: u64 = 4 * 1024 * 1024;

/// Records one signed fitness attestation from an exercise report.
///
/// # Errors
/// Returns an error for an unknown kind, a malformed or failing report, a
/// live identity that cannot be determined, a signer failure, or an
/// attestation that already exists for the same kind and time.
pub(super) async fn run(args: &ReleaseFitnessRunArgs, printer: &Printer) -> Result<()> {
    let (_, config) = MaintainerConfig::load(args.config.as_deref())?;
    let context = FitnessContext::load(&config)?;
    let kind = context.contract.fitness_kind(&args.kind)?;
    let report_bytes = read_report(args.report.as_deref())?;
    let report: FitnessReport = canonical::from_slice(&report_bytes, "fitness report")?;

    let roster = keys::roster_digest(&config)?;
    let live = live_bindings(&config, SurfaceRole::Production, roster)?;
    probe_production(&config).await?;
    let key = attestation_key(&config)?;
    let attestation = report.attest(
        kind,
        &live,
        Sha256Digest::of_bytes(&report_bytes),
        &key.key_id,
    )?;

    let operator_policy = capture::control_file(
        &config.restricted_operator_policy,
        "restricted operator policy",
    )?;
    let provider_revision = evidence_provider_revision(&config)?;
    let release_id = format!("fitness-{}", kind.kind);
    let signed = evidence::sign(
        &config,
        &key,
        &EvidenceScope {
            registry: &config.registry,
            release_id: &release_id,
            plan_digest: roster,
            manifest_digest: None,
            provider_revision: &provider_revision,
            approval_policy_digest: Sha256Digest::of_bytes(&operator_policy),
            artifact_kind: "fitness-attestation",
        },
        &attestation,
    )
    .await?;
    FitnessAttestation::verify_signed_by(&signed, &context.evidence_keys, &trusted_keys(&config)?)?;

    let path = attestation_path(&config.fitness_root, &kind.kind, &attestation.performed_at);
    workdir::write_new_file(&path, &signed)?;
    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.fitness-run-result/v1",
        "kind": kind.kind,
        "performed_at": attestation.performed_at,
        "bindings": attestation.bindings,
        "output": path,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Recorded {} fitness performed at {} in {}",
        kind.kind,
        attestation.performed_at,
        path.display()
    ));
    Ok(())
}

/// Prints each fitness kind's newest attestation, age, and binding status.
///
/// # Errors
/// Returns an error for an unreadable configuration, contract, or fitness
/// root.
pub(super) fn status(args: &ReleaseFitnessStatusArgs, printer: &Printer) -> Result<()> {
    let (_, config) = MaintainerConfig::load(args.config.as_deref())?;
    let context = FitnessContext::load(&config)?;
    let live = live_bindings(
        &config,
        SurfaceRole::Production,
        keys::roster_digest(&config)?,
    )?;
    let attestations = load_attestations(
        &config.fitness_root,
        &context.evidence_keys,
        &trusted_keys(&config)?,
    )?;
    let now = SystemTime::now();
    let statuses = context
        .contract
        .fitness
        .iter()
        .map(|kind| {
            kind_status(
                &context.contract,
                &context.destinations,
                kind,
                &attestations,
                &live,
                now,
            )
        })
        .collect::<Result<Vec<_>>>()?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.fitness-status/v1",
        "kinds": statuses.iter().map(KindStatus::to_json).collect::<Vec<_>>(),
    })) {
        return Ok(());
    }
    for line in render_status(&statuses) {
        println!("{line}");
    }
    Ok(())
}

/// The newest attestation of one kind and how it compares to every demand.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct KindStatus {
    /// Fitness kind.
    pub(super) kind: String,
    /// Newest attestation time and age in seconds, if any.
    pub(super) newest: Option<(String, u64)>,
    /// Each binding and whether the recorded value equals the live one.
    pub(super) bindings: Vec<(String, bool)>,
    /// Each demanding profile, its maximum age, and whether the newest is fresh.
    pub(super) demands: Vec<(String, u64, bool)>,
    /// Destinations of the plan whose profile demands the kind, and whether it satisfies them.
    pub(super) destinations: Vec<(String, bool)>,
}

impl KindStatus {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "kind": self.kind,
            "performed_at": self.newest.as_ref().map(|(time, _)| time),
            "age_seconds": self.newest.as_ref().map(|(_, age)| age),
            "bindings": self.bindings.iter().cloned().collect::<BTreeMap<_, _>>(),
            "demands": self.demands.iter().map(|(profile, max, fresh)| serde_json::json!({
                "profile": profile, "max_age_seconds": max, "fresh": fresh,
            })).collect::<Vec<_>>(),
            "destinations": self.destinations.iter().cloned().collect::<BTreeMap<_, _>>(),
        })
    }
}

/// Computes one kind's status from verified attestations at `now`.
///
/// # Errors
/// Returns an error for a malformed or future attestation time.
pub(super) fn kind_status(
    contract: &QualificationContract,
    destinations: &[PlannedDestination],
    kind: &FitnessKind,
    attestations: &[FitnessAttestation],
    live: &LiveBindings,
    now: SystemTime,
) -> Result<KindStatus> {
    let newest = attestations
        .iter()
        .filter(|attestation| attestation.kind == kind.kind)
        .max_by(|left, right| left.performed_at.cmp(&right.performed_at));
    let age = newest
        .map(|attestation| age_seconds(&attestation.performed_at, now))
        .transpose()?;
    let bindings = kind
        .bindings
        .iter()
        .map(|binding| {
            let recorded =
                newest.and_then(|attestation| attestation.bindings.get(binding.as_str()));
            let matches = match (recorded, live.expected(*binding)) {
                (Some(recorded), Ok(expected)) => *recorded == expected,
                _ => false,
            };
            (binding.as_str().to_owned(), matches)
        })
        .collect::<Vec<_>>();
    let bound = bindings.iter().all(|(_, matches)| *matches);
    let demands = contract
        .profiles
        .iter()
        .filter_map(|profile| {
            profile.fitness.get(&kind.kind).map(|demand| {
                (
                    profile.name.clone(),
                    demand.max_age_seconds,
                    age.is_some_and(|age| is_fresh(age, demand.max_age_seconds)),
                )
            })
        })
        .collect::<Vec<_>>();
    let destinations = destinations
        .iter()
        .filter_map(|destination| {
            demands
                .iter()
                .find(|(profile, _, _)| *profile == destination.profile)
                .map(|(_, _, fresh)| (destination.name.clone(), *fresh && bound))
        })
        .collect();
    Ok(KindStatus {
        kind: kind.kind.clone(),
        newest: newest
            .zip(age)
            .map(|(attestation, age)| (attestation.performed_at.clone(), age)),
        bindings,
        demands,
        destinations,
    })
}

/// Renders `fitness status` lines.
pub(super) fn render_status(statuses: &[KindStatus]) -> Vec<String> {
    let mut lines = Vec::new();
    for status in statuses {
        match &status.newest {
            Some((performed_at, age)) => lines.push(format!(
                "{}: performed {performed_at} ({} ago)",
                status.kind,
                format_age(*age)
            )),
            None => lines.push(format!("{}: no attestation", status.kind)),
        }
        for (profile, max, fresh) in &status.demands {
            lines.push(format!(
                "  profile {profile}: max {} {}",
                format_age(*max),
                if *fresh { "fresh" } else { "expired" }
            ));
        }
        for (binding, matches) in &status.bindings {
            lines.push(format!(
                "  binding {binding}: {}",
                if *matches { "matches" } else { "differs" }
            ));
        }
        for (destination, satisfied) in &status.destinations {
            lines.push(format!(
                "  {} {destination}",
                if *satisfied { "satisfies" } else { "blocks" }
            ));
        }
    }
    lines
}

/// Returns the whole seconds between `performed_at` and `now`.
///
/// # Errors
/// Returns an error for a malformed time or one in the future.
pub(super) fn age_seconds(performed_at: &str, now: SystemTime) -> Result<u64> {
    let performed = humantime::parse_rfc3339(performed_at)
        .with_context(|| format!("parsing fitness time {performed_at}"))?;
    Ok(now
        .duration_since(performed)
        .map_err(|_| anyhow::anyhow!("fitness attestation {performed_at} is in the future"))?
        .as_secs())
}

/// Returns whether an attestation of `age` satisfies `max_age` (inclusive).
pub(super) const fn is_fresh(age: u64, max_age: u64) -> bool {
    age <= max_age
}

/// Formats seconds as the largest two units, such as `3d 4h` or `12m`.
pub(super) fn format_age(seconds: u64) -> String {
    let (days, hours, minutes) = (
        seconds / 86_400,
        seconds % 86_400 / 3_600,
        seconds % 3_600 / 60,
    );
    match (days, hours, minutes) {
        (0, 0, minutes) => format!("{minutes}m"),
        (0, hours, minutes) => format!("{hours}h {minutes}m"),
        (days, hours, _) => format!("{days}d {hours}h"),
    }
}

/// Returns the live bindings of the configured surface for `role`.
///
/// `signer_roster` is the configured roster for `fitness run` and `status`,
/// or a plan's roster when a release's admission is being explained.
///
/// # Errors
/// Returns an error for a malformed tooling or alert configuration digest.
pub(super) fn live_bindings(
    config: &MaintainerConfig,
    role: SurfaceRole,
    signer_roster: Sha256Digest,
) -> Result<LiveBindings> {
    let surface = config.surface(role);
    Ok(LiveBindings {
        registry: config.registry.clone(),
        surface: Some(surface.identity.clone()),
        surface_kind: Some(surface.kind),
        hub_schema: surface.hub_schema.clone(),
        signer_roster: Some(signer_roster),
        tooling: super::super::tooling::detected_digest()?,
        alert_config: config.alert_config_digest()?,
    })
}

/// Loads every attestation under `root` signed by one of `evidence_keys`.
///
/// # Errors
/// Returns an error for an unreadable root or attestation file.
pub(super) fn load_attestations(
    root: &Path,
    evidence_keys: &[String],
    keys: &[TrustedEd25519Key],
) -> Result<Vec<FitnessAttestation>> {
    let mut attestations = Vec::new();
    let kinds = match std::fs::read_dir(root) {
        Ok(kinds) => kinds,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(attestations),
        Err(error) => return Err(error).with_context(|| format!("reading {}", root.display())),
    };
    for kind in kinds {
        let kind = kind?;
        if !kind.file_type()?.is_dir() {
            continue;
        }
        for path in super::observe::files_matching(&kind.path(), "", ".json")? {
            let bytes = capture::control_file(&path, "fitness attestation")?;
            if let Ok(attestation) =
                FitnessAttestation::verify_signed_by(&bytes, evidence_keys, keys)
            {
                attestations.push(attestation);
            }
        }
    }
    Ok(attestations)
}

/// Returns the release-evidence keys fitness attestations verify against.
///
/// # Errors
/// Returns an error for an unreadable key.
pub(super) fn trusted_keys(config: &MaintainerConfig) -> Result<Vec<TrustedEd25519Key>> {
    let mut specs = keys::trusted(config)?;
    if let Ok(evidence) = keys::role_specs(config, SignerRole::ReleaseEvidence) {
        specs.extend(evidence);
    }
    specs.sort();
    specs.dedup();
    super::super::verify::load_trusted_keys(&specs)
}

/// Returns the release-evidence key ids a plan froze.
///
/// # Errors
/// Returns an error when the plan has no release-evidence role.
pub(super) fn planned_evidence_keys(plan: &ReleasePlan) -> Result<Vec<String>> {
    plan.signers
        .iter()
        .find(|requirement| requirement.role == SignerRole::ReleaseEvidence)
        .map(|requirement| requirement.key_ids.clone())
        .context("release plan lacks a release-evidence signer role")
}

/// The fitness policy and signer roster `run` and `status` evaluate against.
struct FitnessContext {
    /// Contract whose fitness kinds and profiles apply.
    contract: QualificationContract,
    /// Release-evidence key ids that may sign attestations.
    evidence_keys: Vec<String>,
    /// Destinations of the newest plan; empty when no plan exists.
    destinations: Vec<PlannedDestination>,
}

impl FitnessContext {
    /// Resolves the contract and roster without requiring a frozen plan.
    ///
    /// # Errors
    /// Returns an error for an unreadable or foreign plan or contract, a
    /// failed Nix export when neither a plan nor `contract.json` exists, or
    /// when neither the configuration nor a plan names a release-evidence
    /// roster.
    fn load(config: &MaintainerConfig) -> Result<Self> {
        let work = newest_work(config);
        let plan = work.as_ref().map(read_plan).transpose()?.flatten();
        if let Some(plan) = &plan
            && plan.registry != config.registry
        {
            bail!("the newest release belongs to registry {}", plan.registry);
        }

        let contract = match (&plan, &work) {
            (Some(plan), _) => plan.qualification.clone(),
            (None, Some(work)) if work.contract().is_file() => read_contract(&work.contract())?,
            (None, _) => {
                let nix = NixRunner::new(0, true).context(
                    "no release plan or contract.json exists under work_root, so the \
                     contract comes from the Nix export; run from the AOS checkout",
                )?;
                super::super::contract::export(&nix)?
            }
        };

        let evidence_keys = match (config.role_keys(SignerRole::ReleaseEvidence), &plan) {
            (Ok(configured), _) => configured.keys.into_iter().map(|key| key.key_id).collect(),
            (Err(_), Some(plan)) => planned_evidence_keys(plan)?,
            (Err(_), None) => bail!(
                "fitness attestations are verified against the release-evidence roster; \
                 configure [signer.roles.release-evidence] or create a release with \
                 aos release new"
            ),
        };

        Ok(Self {
            contract,
            evidence_keys,
            destinations: plan.map(|plan| plan.destinations).unwrap_or_default(),
        })
    }
}

/// Returns the newest release directory under `work_root`, if any.
///
/// A missing or empty `work_root` is the normal state before the first
/// `aos release new`; the contract then comes from the Nix export.
fn newest_work(config: &MaintainerConfig) -> Option<WorkDir> {
    WorkDir::select(config, None).ok()
}

/// Reads a work directory's frozen plan; `None` before `new` froze it.
fn read_plan(work: &WorkDir) -> Result<Option<ReleasePlan>> {
    if !work.plan().is_file() {
        return Ok(None);
    }
    let bytes = capture::control_file(&work.plan(), "release plan")?;
    let plan: ReleasePlan = canonical::from_slice(&bytes, "release plan")?;
    plan.validate()?;
    Ok(Some(plan))
}

/// Reads and validates an exported contract.
fn read_contract(path: &Path) -> Result<QualificationContract> {
    let bytes = capture::control_file(path, "qualification contract")?;
    let contract: QualificationContract = canonical::from_slice(&bytes, "qualification contract")?;
    contract.validate()?;
    Ok(contract)
}

/// Returns the key that signs attestations: `[reviewer]`, else the single
/// release-evidence key.
fn attestation_key(config: &MaintainerConfig) -> Result<RoleKey> {
    if config.reviewer.is_some() {
        return evidence::reviewer_key(config);
    }
    keys::single(config, SignerRole::ReleaseEvidence)
        .context("configure [reviewer] to choose the release-evidence key that signs attestations")
}

/// Returns the configured provider revision of the release-evidence role.
fn evidence_provider_revision(config: &MaintainerConfig) -> Result<String> {
    config
        .signer_roles()?
        .into_iter()
        .find(|configured| configured.role == SignerRole::ReleaseEvidence)
        .and_then(|configured| configured.provider_revision)
        .context("the release-evidence role has no provider_revision")
}

/// Requires a Hub production surface to present its configured identity.
///
/// Static surfaces bind their configured identity; `.aos-surface` is checked
/// by every publication, not by attestation.
async fn probe_production(config: &MaintainerConfig) -> Result<()> {
    let surface = &config.surfaces.production;
    if surface.kind != SurfaceKind::Hub {
        return Ok(());
    }
    readback::verify_deployment(
        &readback::public_client()?,
        &surface.origin,
        &surface.identity,
    )
    .await
    .context("probing the production Hub deployment")
}

/// Reads the exercise report from `path` or standard input.
fn read_report(path: Option<&Path>) -> Result<Vec<u8>> {
    match path {
        Some(path) => capture::control_file(path, "fitness report"),
        None => {
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(MAX_REPORT_BYTES + 1)
                .read_to_end(&mut bytes)
                .context("reading the fitness report from standard input")?;
            if u64::try_from(bytes.len())? > MAX_REPORT_BYTES {
                bail!("fitness report exceeds {MAX_REPORT_BYTES} bytes");
            }
            Ok(bytes)
        }
    }
}

/// Returns the path an attestation of `kind` performed at `performed_at` uses.
pub(super) fn attestation_path(root: &Path, kind: &str, performed_at: &str) -> PathBuf {
    root.join(kind).join(format!("{performed_at}.json"))
}

#[cfg(test)]
#[path = "fitness_tests.rs"]
mod tests;
