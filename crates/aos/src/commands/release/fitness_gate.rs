//! Fitness admission for publication and channel advances.
//!
//! A destination's profile names the fitness kinds it demands and their
//! maximum age. Before publishing to, or advancing, such a destination the
//! coordinator loads every signed attestation under the fitness root
//! (`<root>/<kind>/<performed_at>.json`), keeps those signed by a planned
//! release-evidence key, and requires a fresh attestation per kind whose
//! bindings equal the live identities: the destination surface, its Hub
//! schema (vacuous for static surfaces), the plan's signer roster, and the
//! operator-supplied tooling and alert-configuration digests.

use std::path::Path;

use anyhow::{Context as _, Result};
use aos_release::digest::Sha256Digest;
use aos_release::fitness::{
    FitnessAttestation, LiveBindings, require_destination_fitness, signer_roster_digest,
};
use aos_release::plan::{PlannedDestination, ReleasePlan};
use aos_release::signing::TrustedEd25519Key;

use super::capture;
use super::config::MaintainerConfig;
use crate::cli::ReleaseFitnessInputArgs;

/// Requires every fitness kind the destination's profile demands.
///
/// Destinations whose profile demands no fitness pass without reading the
/// attestation directory.
///
/// # Errors
/// Returns an error when a demanded kind lacks a fresh, correctly bound
/// attestation signed by a planned release-evidence key, the directory is
/// absent or unreadable, or a live digest is malformed.
pub(super) fn require_fitness(
    plan: &ReleasePlan,
    destination: &PlannedDestination,
    input: &ReleaseFitnessInputArgs,
    config: Option<&Path>,
    keys: &[TrustedEd25519Key],
) -> Result<()> {
    let contract = &plan.qualification;
    if contract.profile(&destination.profile)?.fitness.is_empty() {
        return Ok(());
    }
    // Explicit flags win; an explicitly named maintainer configuration
    // supplies the fitness root and live digests it records.
    let config = config
        .map(|path| MaintainerConfig::load(Some(path)).map(|(_, config)| config))
        .transpose()?;
    let root = input
        .fitness
        .clone()
        .or_else(|| config.as_ref().map(|config| config.fitness_root.clone()))
        .with_context(|| {
            format!(
                "{} requires fitness attestations; pass --fitness",
                destination.name
            )
        })?;
    let attestations = load_attestations(&root, plan, keys)?;
    let surface = plan.surface(destination.surface)?;
    let live = LiveBindings {
        registry: plan.registry.clone(),
        surface: Some(surface.identity.clone()),
        surface_kind: Some(surface.kind),
        hub_schema: input.hub_schema.clone().or_else(|| {
            config
                .as_ref()
                .and_then(|config| config.surface(destination.surface).hub_schema.clone())
        }),
        signer_roster: Some(signer_roster_digest(plan)?),
        tooling: match parse_digest(input.tooling_digest.as_deref(), "tooling digest")? {
            Some(digest) => Some(digest),
            None => configured(config.as_ref(), MaintainerConfig::tooling_digest)?,
        },
        alert_config: match parse_digest(
            input.alert_config_digest.as_deref(),
            "alert-config digest",
        )? {
            Some(digest) => Some(digest),
            None => configured(config.as_ref(), MaintainerConfig::alert_config_digest)?,
        },
    };
    require_destination_fitness(
        plan,
        &destination.name,
        &attestations,
        &live,
        &super::journal::now_utc(),
    )
}

/// Loads every attestation that verifies against a planned key.
///
/// Attestations signed by retired keys stay in the store for audit; they are
/// skipped here, so a demanded kind with only such attestations fails closed
/// in [`require_destination_fitness`].
fn load_attestations(
    root: &Path,
    plan: &ReleasePlan,
    keys: &[TrustedEd25519Key],
) -> Result<Vec<FitnessAttestation>> {
    let mut attestations = Vec::new();
    for kind in std::fs::read_dir(root)
        .with_context(|| format!("reading fitness root {}", root.display()))?
    {
        let kind = kind?;
        if !kind.file_type()?.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(kind.path())? {
            let path = entry?.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let bytes = capture::control_file(&path, "fitness attestation")?;
            if let Ok(attestation) = FitnessAttestation::verify_signed(&bytes, plan, keys) {
                attestations.push(attestation);
            }
        }
    }
    Ok(attestations)
}

/// Reads one live digest from the maintainer configuration, when present.
fn configured(
    config: Option<&MaintainerConfig>,
    digest: fn(&MaintainerConfig) -> Result<Option<Sha256Digest>>,
) -> Result<Option<Sha256Digest>> {
    config.map_or(Ok(None), digest)
}

fn parse_digest(value: Option<&str>, label: &str) -> Result<Option<Sha256Digest>> {
    value
        .map(|value| Sha256Digest::parse(value).with_context(|| format!("parsing {label}")))
        .transpose()
}
