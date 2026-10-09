//! Native projection of an authorized storage policy and canonical disk plan.
//!
//! The admitted source descriptor supplies the resolved module/artifact context
//! and retains authored configuration sources. Authorized host bytes
//! and observational facts join those exact sources in the ordinary package
//! module fixed point; no image evaluator or build package set is imported.

use std::fs;
use std::path::{Path, PathBuf};

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
use crate::store::verification::dump_store_path_identity_in;

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

/// Projects a validated disk plan from retained authorized module sources.
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
    let nix_store = store_executable()?;
    let mut temporary_roots =
        crate::store::temp_roots::TemporaryRoots::open(&nix_store, cancellation)?;
    temporary_roots.retain(
        [&parameters.evaluation_context, &parameters.authorized_input]
            .into_iter()
            .map(|path| retained_root(path))
            .collect::<Result<Vec<_>>>()?,
        cancellation,
    )?;
    let authorized_bytes = crate::native_deployment::read_regular_store_document_in(
        &parameters.authorized_input,
        &nix_store,
        cancellation,
    )?;
    ensure!(
        u64::try_from(authorized_bytes.len())? <= ABILITY_LIMITS_V1.max_document_bytes,
        "retained authorization exceeds the document bound"
    );
    ensure!(
        Sha256Digest::of_bytes(&authorized_bytes) == parameters.authorized_input_sha256,
        "retained authorization differs from its content commitment"
    );
    let authorized: AuthorizedProvisioningInput =
        aos_contract::canonical::from_slice(&authorized_bytes, "authorized provisioning input")?;
    validate_authorized_provisioning_input(&authorized)?;

    let descriptor =
        EvaluationInput::read_in(&parameters.evaluation_context, &nix_store, cancellation)?;
    temporary_roots.retain(projection_source_roots(&descriptor)?, cancellation)?;
    let (library_root, _) = crate::deployment::nix::store_root_and_suffix(&descriptor.library)?;
    ensure!(
        library_root == PathBuf::from(&authorized.base_library.store_path),
        "native evaluator library differs from the admitted authorization library"
    );
    let (library_hash, _) =
        dump_store_path_identity_in(&authorized.base_library.store_path, Some(&nix_store))?;
    ensure!(
        library_hash == descriptor.library_nar_hash
            && library_hash.to_string() == authorized.base_library.nar_hash,
        "native evaluator library NAR differs from its authorization commitment"
    );

    let scratch = tempfile::Builder::new()
        .prefix("aos-native-provisioning-")
        .tempdir()?;
    // Protect fixed source identities before import and through projection.
    // Host adoption reconstructs these bytes from the separately rooted
    // authorization receipt and evaluates the host graph before dispatch.
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
    let mut retained_inputs = descriptor.supplemental_inputs;
    retained_inputs.extend([
        parameters.evaluation_context.clone(),
        parameters.authorized_input,
    ]);
    let declarations = crate::native_deployment::retained_declarations(
        &descriptor.package_envelopes,
        descriptor.os_release.as_ref(),
        &nix_store,
    )?;
    let evaluator = Evaluation {
        os_release: descriptor.os_release.clone(),
        os_requirements: declarations.os_requirements,
        package_releases: declarations.package_releases,
        nix_store: nix_store.clone(),
        library: descriptor.library,
        scope: descriptor.scope,
        packages: descriptor.packages,
        module_requirements: descriptor
            .resolution_lock
            .as_ref()
            .map_or_else(Vec::new, |lock| lock.module_requirements()),
        configuration,
        evaluation_input: Some(parameters.evaluation_context.clone()),
        retained_inputs,
    };

    let storage = evaluator.provisioning_storage(scratch.path(), timeout_ms, cancellation)?;
    let plan: ProvisioningPlan =
        serde_json::from_value(json!({"schema":"aos.provisioning-plan/v1", "storage":storage}))?;
    let marker_uuid = marker_uuid_for_source(&parameters.marker, authorized.source)?;
    let plan = canonicalize_provisioning_plan(
        plan,
        authorized.source,
        parameters.request.measured_boot,
        &marker_uuid,
    )?;
    // Persist the exact validated plan before disk mutation. Full host graph
    // evaluation belongs to host admission, after storage has been prepared.
    let canonical_plan = String::from_utf8(aos_contract::canonical::to_vec(&plan)?)?;
    Ok(json!({"provisioning_plan":plan,"canonical_plan":canonical_plan}))
}

// Payload catalogs remain authenticated data; projection retains only sources.
fn projection_source_roots(descriptor: &EvaluationInput) -> Result<Vec<String>> {
    std::iter::once(&descriptor.library)
        .chain(descriptor.configuration.iter())
        .chain(descriptor.runtime_configuration.iter())
        .chain(descriptor.supplemental_inputs.iter())
        .chain(descriptor.module_envelopes.values())
        .chain(descriptor.package_envelopes.values())
        .map(|path| retained_root(path))
        .chain(
            descriptor
                .packages
                .modules
                .iter()
                .map(|module| retained_root(Path::new(&module.config_root))),
        )
        .collect()
}

fn retained_root(path: &Path) -> Result<String> {
    let (root, _) = crate::deployment::nix::store_root_and_suffix(path)?;
    Ok(root
        .to_str()
        .context("retained source root is not UTF-8")?
        .to_owned())
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
    #[ignore = "requires the source-built boot fixture containing actual Nix result declarations"]
    fn source_built_provisioning_results_match_declared_wire_contracts() -> Result<()> {
        let fixture = PathBuf::from(
            std::env::var_os("AOS_BOOT_CONFIGURATION_FIXTURE")
                .context("source-built boot fixture is required")?,
        );
        let graph_path = fixture
            .parent()
            .context("boot fixture must have a parent directory")?
            .join("provisioning-wire-graph.json");
        let graph =
            aos_ability_plan::module_graph::CheckedModuleGraph::decode(&fs::read(graph_path)?)?;
        let operation = |ability: &str| {
            graph
                .graph()
                .nodes
                .values()
                .find(|node| node.identity.iter().any(|part| part == ability))
                .context("fixture must retain the actual provisioning operation")
        };
        let plan_node = operation("provisioningEvaluation")?;
        let marker_node = operation("provisioningMarker")?;

        // Nullable input fields are deliberately absent. Canonicalization must
        // still emit every field required by the declaration-derived wire type.
        let intent: ProvisioningPlan = serde_json::from_value(json!({
            "schema": "aos.provisioning-plan/v1",
            "storage": {"partitions": {"var": {
                "label": "var", "type": "linux-generic", "sizeMin": "4G",
                "weight": 1000, "grow": true, "growFs": true, "priority": 9000
            }}}
        }))?;
        let marker_uuid = "01234567-89ab-4def-8123-456789abcdef";
        let plan = canonicalize_provisioning_plan(
            intent,
            CanonicalProvisioningSource::Operator,
            false,
            marker_uuid,
        )?;
        assert!(plan.partitions["var"].size_max.is_none());
        assert!(plan.partitions["var"].format.is_none());

        let plan_results = json!({
            "canonical_plan": String::from_utf8(aos_contract::canonical::to_vec(&plan)?)?,
            "provisioning_plan": plan,
        });
        assert!(plan_results["provisioning_plan"]["partitions"]["var"]["size_max"].is_null());
        assert!(plan_results["provisioning_plan"]["partitions"]["var"]["format"].is_null());
        plan_node.check_results(&plan_results)?;

        for field in ["size_max", "format"] {
            let mut omitted = plan_results.clone();
            omitted["provisioning_plan"]["partitions"]["var"]
                .as_object_mut()
                .context("canonical partition must be an object")?
                .remove(field)
                .context("canonical partition must retain its nullable field")?;
            assert!(
                plan_node.check_results(&omitted).is_err(),
                "omitted {field}"
            );
        }

        for state in [
            ProvisioningMarkerState::Absent,
            ProvisioningMarkerState::Completed,
            ProvisioningMarkerState::Pending,
            ProvisioningMarkerState::Indeterminate,
        ] {
            let completed = state == ProvisioningMarkerState::Completed;
            let marker = ProvisioningMarkerObservation {
                schema: "aos.storage.provisioning-marker-observation/v1".into(),
                state,
                source: completed.then_some(CanonicalProvisioningSource::Operator),
                marker_uuid: completed.then(|| marker_uuid.into()),
            };
            validate_provisioning_marker_observation(&marker)?;
            let marker_results = json!({"marker": marker});
            marker_node.check_results(&marker_results)?;

            for field in ["source", "marker_uuid"] {
                let mut omitted = marker_results.clone();
                omitted["marker"]
                    .as_object_mut()
                    .context("marker result must be an object")?
                    .remove(field)
                    .context("marker result must retain its nullable field")?;
                assert!(
                    marker_node.check_results(&omitted).is_err(),
                    "omitted {field}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn projection_retains_source_and_proof_roots_without_payloads() {
        let source = "/nix/store/00000000000000000000000000000000-source";
        let proof = "/nix/store/11111111111111111111111111111111-proof";
        let descriptor = EvaluationInput {
            os_release: None,
            package_envelopes: std::collections::BTreeMap::from([(
                "/nix/store/22222222222222222222222222222222-payload".into(),
                PathBuf::from(source),
            )]),
            schema: "aos.package.evaluation-input".into(),
            library: PathBuf::from(source).join("default.nix"),
            library_nar_hash: Sha256Digest::of_bytes(b"library"),
            scope: vec!["host".into()],
            configuration: vec![PathBuf::from(source).join("baseline.nix")],
            runtime_configuration: vec![PathBuf::from(source).join("host.nix")],
            supplemental_inputs: vec![proof.into()],
            module_envelopes: Default::default(),
            resolution_lock: None,
            packages: crate::deployment::model::ResolvedPackages {
                system: "x86_64-linux".into(),
                modules: vec![],
                artifacts: vec![crate::deployment::model::Artifact {
                    name: "host-only-payload".into(),
                    version: "1".into(),
                    path: "/nix/store/22222222222222222222222222222222-payload".into(),
                    outputs: Default::default(),
                    main_program: None,
                }],
            },
        };

        let roots = projection_source_roots(&descriptor).unwrap();

        assert!(roots.iter().all(|root| root == source || root == proof));
        assert!(roots.iter().any(|root| root == proof));
        assert!(!roots.iter().any(|root| root.ends_with("-payload")));
    }

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
            retained_root(Path::new(
                "/nix/store/00000000000000000000000000000000-source/module.nix"
            ))
            .is_ok()
        );
        assert!(retained_root(Path::new("/tmp/host.nix")).is_err());
        assert!(retained_root(Path::new("/nix/store/../host.nix")).is_err());
    }
}
