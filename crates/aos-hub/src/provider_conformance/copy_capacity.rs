//! Explicit installed Copy ceilings beneath one accepted whole-isolate capacity.
//!
//! The operator declaration restricts scheduling; it is not a provider peak,
//! permission or attestation. The existing independently signed Direct artifact
//! supplies the actual runtime ceiling, source, script and protected profiles.
//! No input or accepted artifact is rewritten by this read-only projection.
//!
//! ```text
//! declaration = {version:1, deployment_id, public_origin, reviewer_key_id,
//!                domains:[{producer_profile_digest, admitted_provider_requests}]}
//! output = {version:1, ceiling_semantics:"installed_configuration",
//!           policy:{version:1, deployment_id, source_digest, script_version,
//!                   maximum_provider_requests}, copy_configuration_version:2,
//!           domains:[{producer_profile_digest, binding_id, binding_stable_id,
//!                     binding_resource_version, admitted_provider_requests}],
//!           qualification_artifact_sha256, declaration_sha256,
//!           reviewer_public_key_sha256, runtime_qualification_digest}
//! ```

use std::{collections::BTreeSet, path::Path};

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::direct_upload::{
    DirectProtectedExternalProfile, DirectWorkerQualificationArtifact,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::journal;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    version: u8,
    deployment_id: String,
    public_origin: String,
    reviewer_key_id: String,
    domains: Vec<DomainCeiling>,
}

/// One operator-selected scheduling restriction for an exact installed profile.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DomainCeiling {
    pub(super) producer_profile_digest: String,
    pub(super) admitted_provider_requests: u32,
}

/// Resolves declared ceilings to complete profiles without changing their runtime.
pub(super) fn map_domains(
    profiles: &[DirectProtectedExternalProfile],
    configured: u32,
    declarations: &[DomainCeiling],
) -> Result<Vec<Value>> {
    ensure!(
        (3..=32).contains(&configured) && !declarations.is_empty() && declarations.len() <= 16,
        "copy capacity requires a qualified pair and bounded domain selection"
    );
    let mut selected_profiles = BTreeSet::new();
    let mut bindings = BTreeSet::new();
    let mut domains = Vec::with_capacity(declarations.len());
    for declaration in declarations {
        ensure!(
            configured <= declaration.admitted_provider_requests
                && declaration.admitted_provider_requests <= 32
                && selected_profiles.insert(&declaration.producer_profile_digest),
            "copy declared ceiling is smaller than the actual pool or ambiguous"
        );
        let matches = profiles
            .iter()
            .filter_map(|profile| match profile.digest() {
                Ok(digest) if digest == declaration.producer_profile_digest => Some(Ok(profile)),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            matches.len() == 1,
            "copy declared profile is absent or ambiguous"
        );
        let profile = matches[0];
        ensure!(
            profile
                .runtime_qualification
                .maximum_parallel_provider_requests
                .get()
                == u64::from(configured),
            "copy profile differs from actual whole-isolate capacity"
        );
        let association = &profile.profile.read_cohort.association;
        ensure!(
            bindings.insert(association.binding_id.get()),
            "copy declared domains repeat an actual binding"
        );
        domains.push(json!({
            "producer_profile_digest": declaration.producer_profile_digest,
            "binding_id": association.binding_id.get().to_string(),
            "binding_stable_id": association.binding_stable_id,
            "binding_resource_version": association.binding_resource_version.get().to_string(),
            "admitted_provider_requests": declaration.admitted_provider_requests,
        }));
    }
    Ok(domains)
}

pub(super) fn project(
    artifact_file: &Path,
    reviewer_public_key_file: &Path,
    declaration_file: &Path,
    output: &Path,
) -> Result<String> {
    let artifact_bytes = journal::read(artifact_file, 4 * 1024 * 1024, false)?;
    let artifact: DirectWorkerQualificationArtifact = serde_json::from_slice(&artifact_bytes)?;
    let declaration_bytes = journal::read(declaration_file, 16 * 1024, true)?;
    let declaration: Declaration = serde_json::from_slice(&declaration_bytes)?;
    ensure!(
        serde_json::to_vec(&declaration)? == declaration_bytes
            && declaration.version == 1
            && declaration.reviewer_key_id == artifact.reviewer_key_id,
        "copy capacity declaration is noncanonical or selects another reviewer"
    );
    let reviewer_bytes = journal::read(reviewer_public_key_file, 64, false)?;
    let reviewer =
        std::str::from_utf8(&reviewer_bytes).context("copy capacity reviewer key is not UTF-8")?;
    // Existing signature, audience, time and measurement validation remains
    // the sole acceptance check. A declaration cannot alter any of its facts.
    artifact.verify(
        &declaration.deployment_id,
        &declaration.public_origin,
        reviewer,
        u64::try_from(aos_hub_core::clock::now_unix_secs())?,
    )?;
    let configured = u32::try_from(
        artifact
            .evidence
            .runtime
            .maximum_parallel_provider_requests
            .get(),
    )?;
    let domains = map_domains(
        &artifact.evidence.external_profiles,
        configured,
        &declaration.domains,
    )?;
    let selected = json!({
        "version": 1,
        "ceiling_semantics": "installed_configuration",
        "qualification_artifact_sha256": journal::digest(&artifact_bytes),
        "declaration_sha256": journal::digest(&declaration_bytes),
        "reviewer_public_key_sha256": journal::digest(&reviewer_bytes),
        "runtime_qualification_digest": artifact.evidence.runtime.qualification_digest,
        "policy": {
            "version": 1,
            "deployment_id": artifact.deployment_id,
            "source_digest": artifact.source_digest,
            "script_version": artifact.script_version,
            "maximum_provider_requests": configured,
        },
        "copy_configuration_version": 2,
        "domains": domains,
    });
    journal::write_new(output, &selected)
}

#[cfg(test)]
mod tests;
