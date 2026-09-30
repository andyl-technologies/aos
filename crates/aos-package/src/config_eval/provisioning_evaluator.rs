//! Native evaluation of an authorized provisioning policy and deployment.
//!
//! The admitted source descriptor supplies the resolved module/artifact context
//! and retains authored configuration sources. Authorized host bytes
//! and observational facts join those exact sources in the ordinary package
//! module fixed point; no image evaluator or build package set is imported.

use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::ABILITY_LIMITS_V1;
use aos_ability_runtime::adapter::CancellationToken;
use aos_contract::Sha256Digest;
use aos_storage_provisioning::{
    AuthorizedProvisioningInput, CanonicalProvisioningSource, ProvisioningIntent,
    ProvisioningMarkerObservation, ProvisioningMarkerState, ProvisioningPlan,
    canonicalize_provisioning_plan, validate_authorized_provisioning_input,
    validate_provisioning_intent, validate_provisioning_marker_observation,
};
use rand::RngCore as _;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::deployment::evaluation::Evaluation;
use crate::native_deployment::EvaluationInput;
use crate::store::verification::dump_store_path_identity;

use super::provisioning_sources::{
    add_fixed_eval_host_source, add_fixed_input_to_store, store_executable,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvaluationParameters {
    evaluation_context: PathBuf,
    request: ProvisioningIntent,
    authorized_input: PathBuf,
    authorized_input_sha256: Sha256Digest,
    marker: ProvisioningMarkerObservation,
}

/// Evaluates a native transaction and validated disk plan from retained sources.
///
/// # Errors
/// Returns an error for changed authorized bytes or library identity, malformed
/// source context, pending markers, invalid projected plans, or pure evaluation
/// failure, timeout, or cancellation.
pub(crate) fn evaluate(
    parameters: EvaluationParameters,
    timeout_ms: u64,
    cancellation: &CancellationToken,
) -> Result<Value> {
    validate_provisioning_intent(&parameters.request)?;
    validate_provisioning_marker_observation(&parameters.marker)?;
    let authorized_bytes = read_immutable(&parameters.authorized_input)?;
    ensure!(
        Sha256Digest::of_bytes(&authorized_bytes) == parameters.authorized_input_sha256,
        "retained authorization differs from its content commitment"
    );
    let authorized: AuthorizedProvisioningInput =
        aos_contract::canonical::from_slice(&authorized_bytes, "authorized provisioning input")?;
    validate_authorized_provisioning_input(&authorized)?;

    let descriptor = EvaluationInput::read_in(
        &parameters.evaluation_context,
        &store_executable()?,
        cancellation,
    )?;
    let library_root = store_root(&descriptor.library)?;
    ensure!(
        library_root == Path::new(&authorized.base_library.store_path),
        "native evaluator library differs from the admitted authorization library"
    );
    let (library_hash, _) = dump_store_path_identity(&authorized.base_library.store_path)?;
    ensure!(
        library_hash == descriptor.library_nar_hash
            && library_hash.to_string() == authorized.base_library.nar_hash,
        "native evaluator library NAR differs from its authorization commitment"
    );

    let scratch = tempfile::Builder::new()
        .prefix("aos-native-provisioning-")
        .tempdir()?;
    // Protect fixed source identities before import and through both pure
    // evaluations. Host adoption reconstructs these bytes from the separately
    // rooted authorization receipt; the transaction is provisioning evidence.
    let mut temporary_roots =
        crate::store::temp_roots::TemporaryRoots::open(&store_executable()?, cancellation)?;
    let host_path = scratch.path().join("host.nix");
    fs::write(
        &host_path,
        authorized.host_module.as_deref().unwrap_or("{}\n"),
    )?;
    let host = add_fixed_eval_host_source(
        &host_path,
        scratch.path(),
        timeout_ms,
        cancellation,
        &mut temporary_roots,
    )?;
    let facts: aos_metadata::fetcher::Facts =
        serde_json::from_value(authorized.facts.value.clone())?;
    ensure!(
        aos_metadata::facts_render::canonicalize_host_facts(&facts)? == facts,
        "authorized observational facts are not canonical"
    );
    let facts_path = scratch.path().join("observational-facts.nix");
    fs::write(
        &facts_path,
        aos_metadata::facts_render::render_host_facts_nix(&facts),
    )?;
    let facts =
        add_fixed_input_to_store(&facts_path, timeout_ms, cancellation, &mut temporary_roots)?;
    let mut configuration = descriptor.configuration;
    configuration.extend(descriptor.runtime_configuration);
    configuration.extend([host, facts]);
    let evaluator = Evaluation {
        library: descriptor.library,
        scope: descriptor.scope,
        packages: descriptor.packages,
        configuration,
        evaluation_input: Some(parameters.evaluation_context.clone()),
        retained_inputs: vec![parameters.evaluation_context, parameters.authorized_input],
    };

    let storage = evaluator.project(
        &["aos".into(), "provisioning".into(), "storage".into()],
        scratch.path(),
        timeout_ms,
        cancellation,
    )?;
    let plan: ProvisioningPlan =
        serde_json::from_value(json!({"schema":"aos.provisioning-plan/v1", "storage":storage}))?;
    let marker_uuid = marker_uuid_for_source(&parameters.marker, authorized.source)?;
    let plan = canonicalize_provisioning_plan(
        plan,
        authorized.source,
        parameters.request.measured_boot,
        &marker_uuid,
    )?;
    let deployment = evaluator.evaluate(scratch.path(), timeout_ms, cancellation)?;
    let transaction = String::from_utf8(deployment.canonical_bytes()?)?;
    Ok(json!({"provisioning_plan":plan,"canonical_transaction":transaction}))
}

fn store_root(path: &Path) -> Result<&Path> {
    ensure!(
        path.is_absolute()
            && path.starts_with("/nix/store")
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "retained input is not a normalized immutable store path"
    );
    path.ancestors()
        .find(|ancestor| ancestor.parent() == Some(Path::new("/nix/store")))
        .context("retained input has no store root")
}

fn read_immutable(path: &Path) -> Result<Vec<u8>> {
    let root = store_root(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "retained input is not a regular immutable file"
    );
    ensure!(
        fs::canonicalize(path)?.starts_with(root),
        "retained input escapes its store root"
    );
    ensure!(
        metadata.len() <= ABILITY_LIMITS_V1.max_document_bytes,
        "retained input exceeds the document bound"
    );
    Ok(fs::read(path)?)
}

fn marker_uuid_for_source(
    marker: &ProvisioningMarkerObservation,
    source: CanonicalProvisioningSource,
) -> Result<String> {
    validate_provisioning_marker_observation(marker)?;
    match marker.state {
        ProvisioningMarkerState::Absent => Ok(generate_marker_uuid()),
        ProvisioningMarkerState::Completed => {
            ensure!(
                marker.source == Some(source),
                "current source differs from committed provisioning source"
            );
            marker
                .marker_uuid
                .clone()
                .context("completed marker has no UUID")
        }
        ProvisioningMarkerState::Pending => {
            anyhow::bail!("pending provisioning marker requires explicit recovery")
        }
        ProvisioningMarkerState::Indeterminate => {
            anyhow::bail!("provisioning marker state is indeterminate")
        }
    }
}

fn generate_marker_uuid() -> String {
    let mut bytes = [0_u8; 16];
    #[allow(clippy::disallowed_methods)]
    rand::rng().fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_markers_and_source_changes_require_explicit_recovery() {
        let mut marker = ProvisioningMarkerObservation {
            schema: "aos.storage.provisioning-marker-observation/v1".into(),
            state: ProvisioningMarkerState::Pending,
            source: None,
            marker_uuid: None,
        };
        assert!(marker_uuid_for_source(&marker, CanonicalProvisioningSource::Operator).is_err());
        marker.state = ProvisioningMarkerState::Completed;
        marker.source = Some(CanonicalProvisioningSource::Fallback);
        marker.marker_uuid = Some("01234567-89ab-4def-8123-456789abcdef".into());
        assert!(marker_uuid_for_source(&marker, CanonicalProvisioningSource::Operator).is_err());
        assert_eq!(
            marker_uuid_for_source(&marker, CanonicalProvisioningSource::Fallback).unwrap(),
            marker.marker_uuid.unwrap()
        );
    }

    #[test]
    fn retained_sources_require_normalized_store_paths() {
        assert!(
            store_root(Path::new(
                "/nix/store/00000000000000000000000000000000-source/module.nix"
            ))
            .is_ok()
        );
        assert!(store_root(Path::new("/tmp/host.nix")).is_err());
        assert!(store_root(Path::new("/nix/store/../host.nix")).is_err());
    }
}
