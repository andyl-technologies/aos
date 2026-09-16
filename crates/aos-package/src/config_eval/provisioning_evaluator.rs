//! Complete initrd configuration evaluation for storage provisioning.
//!
//! The evaluator consumes the metadata provider's typed authorization result
//! and the selected package-store read view. One pure Nix invocation evaluates
//! the frozen initrd module fixed point and returns both the canonical
//! configuration manifest and its storage-policy projection.

use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::{
    ABILITY_LIMITS_V1, ArtifactReference, LocalKey, MAX_TRANSACTION_BLOB_BYTES,
};
use aos_contract::Sha256Digest;
use aos_provider_protocol::{TRANSACTION_BLOB_OUTPUT_TYPE, TransactionBlobOutput};
use aos_storage_provisioning::{
    AuthorizedProvisioningInput, CanonicalProvisioningPlan, CanonicalProvisioningSource,
    ProvisioningIntent, ProvisioningMarkerObservation, ProvisioningMarkerState, ProvisioningPlan,
    ProvisioningTrustMode, canonicalize_provisioning_plan,
    validate_authorized_provisioning_input, validate_provisioning_intent,
    validate_provisioning_marker_observation,
};
use rand::RngCore as _;
use serde::Deserialize;
use tempfile::Builder;

use super::materialize::{ConfigManifest, HostNixInput, InstanceFactsInput};
use super::{
    EvaluatorInput, RetainedHostInputs, add_fixed_eval_host_source, add_fixed_input_to_store,
    read_base_lib_abi_hash, sha256_identity,
};

const RESULT_SCHEMA: &str = "aos.configuration.provisioning-evaluation-result/v1";
pub(crate) const MANIFEST_SLOT: &str = "configuration-manifest";

/// Carries one checked evaluator invocation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvaluationParameters {
    /// Selects the immutable package-store view and initrd static contract.
    pub(crate) store_view: super::store_view::StoreViewLocator,
    /// Carries the durable storage-provisioning intent.
    pub(crate) request: ProvisioningIntent,
    /// Carries the only value authorized to supply host configuration bytes.
    pub(crate) authorized_input: AuthorizedInputSource,
    /// Carries the durable marker state used to close the canonical plan.
    pub(crate) marker: ProvisioningMarkerObservation,
}

/// Selects the protected authorization result within the durable stage graph.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum AuthorizedInputSource {
    /// Consumes the authorizer result directly within the initrd transaction.
    DirectResult {
        /// Carries the exact typed protected result.
        input: AuthorizedProvisioningInput,
    },
    /// Reloads the same canonical result from its retained persistent artifact.
    RetainedArtifact {
        /// Locates the provider-reverified immutable flat object.
        artifact: ArtifactReference,
        /// Authenticates the exact canonical serialized input bytes.
        content_sha256: Sha256Digest,
    },
}

/// Carries canonical evaluator outputs and their graph-bound result envelope.
pub(crate) struct EvaluationOutput {
    /// Exact canonical configuration manifest bytes.
    pub(crate) manifest: Vec<u8>,
    /// Canonical storage plan projected from the same fixed point.
    pub(crate) provisioning_plan: CanonicalProvisioningPlan,
    /// Small typed result returned after the blob transport publishes bytes.
    pub(crate) result: EvaluationResult,
}

/// Carries the non-path identity of one completed provisioning evaluation.
#[derive(Debug, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvaluationResult {
    /// Carries [`RESULT_SCHEMA`].
    pub(crate) schema: &'static str,
    /// Requests runtime publication of the canonical manifest byte slot.
    pub(crate) manifest_blob: TransactionBlobOutput,
    /// Authenticates the exact canonical manifest bytes.
    pub(crate) manifest_sha256: Sha256Digest,
    /// Authenticates the canonical plan returned beside the manifest.
    pub(crate) provisioning_plan_sha256: Sha256Digest,
    /// Names the initrd static contract authenticated by the selected view.
    pub(crate) static_contract: String,
    /// Authenticates operator host bytes when the operator arm is selected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) host_module_sha256: Option<String>,
    /// Retains the explicitly observational facts commitment.
    pub(crate) instance_facts_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteInitrdProjection {
    manifest: ConfigManifest,
    provisioning: ProvisioningPlan,
}

/// Evaluates one authorized input through the complete initrd fixed point.
///
/// # Errors
///
/// Returns an error when authorization, marker, or store-view commitments are
/// invalid; the immutable base-library identity differs; the complete initrd
/// fixed point fails; or either canonical result exceeds its transport bound.
pub(crate) fn evaluate(parameters: EvaluationParameters) -> Result<EvaluationOutput> {
    validate_provisioning_intent(&parameters.request)?;
    validate_provisioning_marker_observation(&parameters.marker)?;
    parameters
        .store_view
        .validate()
        .context("validating the selected initrd package-store read view")?;
    let authorized_input = resolve_authorized_input(parameters.authorized_input)?;
    validate_authorized_provisioning_input(&authorized_input)?;

    let scratch = Builder::new()
        .prefix("aos-provisioning-evaluation-")
        .tempdir()
        .context("creating private provisioning evaluation scratch")?;
    let eval_root = scratch.path().join("eval");
    fs::create_dir(&eval_root).context("creating provisioning evaluator root")?;
    let host_nix = prepare_host_input(scratch.path(), &authorized_input)?;
    let facts_json = prepare_facts_input(scratch.path(), &authorized_input)?;
    let pinned_host = add_fixed_eval_host_source(&host_nix, &eval_root)
        .context("pinning authorized provisioning host input")?;
    let pinned_facts = add_fixed_input_to_store(&facts_json)
        .context("pinning observational provisioning facts")?;

    let base_lib = PathBuf::from(&authorized_input.base_library.store_path);
    let readable_base_lib = parameters.store_view.read_path(&base_lib)?;
    let module_abi = read_module_abi(&readable_base_lib)?;
    let abi_hash = read_base_lib_abi_hash(&readable_base_lib, module_abi)?;
    ensure!(
        abi_hash == authorized_input.base_library.abi_hash,
        "authorized base-library ABI differs from the immutable module library"
    );
    let retained = retained_inputs(&authorized_input, &pinned_host, &pinned_facts)?;
    let mut projection = evaluate_complete_initrd(
        &parameters.store_view,
        &base_lib,
        &pinned_host,
        &pinned_facts,
    )?;
    projection.manifest.inputs.host_nix = retained.host_nix;
    projection.manifest.inputs.instance_facts = retained.instance_facts;
    projection.manifest.validate()?;

    let marker_uuid = marker_uuid_for_source(&parameters.marker, authorized_input.source)?;
    let provisioning_plan = canonicalize_provisioning_plan(
        projection.provisioning,
        authorized_input.source,
        parameters.request.measured_boot,
        &marker_uuid,
    )?;
    let manifest = aos_contract::canonical::to_vec(&projection.manifest)
        .context("encoding canonical configuration manifest")?;
    ensure!(
        manifest.len() as u64 <= MAX_TRANSACTION_BLOB_BYTES,
        "canonical configuration manifest exceeds the transaction blob bound"
    );
    let plan_bytes = aos_contract::canonical::to_vec(&provisioning_plan)
        .context("encoding canonical provisioning plan")?;
    ensure!(
        plan_bytes.len() as u64 <= ABILITY_LIMITS_V1.max_document_bytes,
        "canonical provisioning plan exceeds the ability document bound"
    );

    let result = EvaluationResult {
        schema: RESULT_SCHEMA,
        manifest_blob: TransactionBlobOutput {
            kind: TRANSACTION_BLOB_OUTPUT_TYPE.into(),
            slot: LocalKey::new(MANIFEST_SLOT)?,
        },
        manifest_sha256: Sha256Digest::of_bytes(&manifest),
        provisioning_plan_sha256: Sha256Digest::of_bytes(&plan_bytes),
        static_contract: parameters
            .store_view
            .static_contract
            .to_string_lossy()
            .into_owned(),
        host_module_sha256: authorized_input.host_module_sha256,
        instance_facts_sha256: authorized_input.facts.sha256,
    };
    Ok(EvaluationOutput {
        manifest,
        provisioning_plan,
        result,
    })
}

fn evaluate_complete_initrd(
    store_view: &super::store_view::StoreViewLocator,
    base_lib: &Path,
    host_nix: &Path,
    facts_json: &Path,
) -> Result<CompleteInitrdProjection> {
    let store = super::selected_eval_store_uri()?;
    let base = super::stock::locked_evaluator_input_in(
        &EvaluatorInput {
            identity: base_lib.to_path_buf(),
            read_path: store_view.read_path(base_lib)?,
        },
        None,
        store.as_deref(),
    )?;
    let host = super::stock::locked_evaluator_input_in(
        &EvaluatorInput::canonical(host_nix.to_path_buf()),
        None,
        store.as_deref(),
    )?;
    let facts = fs::read(facts_json)
        .with_context(|| format!("reading facts {}", facts_json.display()))?;
    let facts: aos_metadata::fetcher::Facts = serde_json::from_slice(&facts)
        .with_context(|| format!("parsing facts {}", facts_json.display()))?;
    let facts_module = aos_metadata::facts_render::render_host_facts_nix(&facts);
    let store_view_json = serde_json::to_string(store_view)
        .context("encoding the selected initrd package-store read view")?;
    let expression = complete_initrd_expression(&base, &host, &facts_module, &store_view_json);

    let mut command = super::stock::pure_eval_command_in(
        store.as_deref(),
        Some(store_view.read_root.as_path()),
    )?;
    command.arg("-");
    let output = super::stock::output_with_expression(&mut command, &expression)
        .context("spawning complete initrd configuration evaluation")?;
    if !output.status.success() {
        anyhow::bail!(
            "complete initrd configuration evaluation failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    serde_json::from_slice(&output.stdout)
        .context("parsing complete initrd configuration projection")
}

fn complete_initrd_expression(
    base: &str,
    host: &str,
    facts_module: &str,
    store_view_json: &str,
) -> String {
    format!(
        "# Generated by the AOS complete initrd evaluator; do not edit.\n\
         let\n\
        \x20 baseLib = import {base};\n\
        \x20 hostModule = import {host};\n\
        \x20 factsModule = (\n{facts_module}\n\x20 );\n\
        \x20 storeView = builtins.fromJSON {store_view};\n\
        \x20 system = baseLib.evalCompleteInitrdConfig {{\n\
        \x20   inherit storeView;\n\
        \x20   operatorModules = [ hostModule ];\n\
        \x20   factsModules = [ factsModule ];\n\
        \x20 }};\n\
         in {{\n\
        \x20 manifest = system.config.system.build.configManifest;\n\
        \x20 provisioning = {{\n\
        \x20   schema = \"aos.provisioning-plan/v1\";\n\
        \x20   storage = system.config.aos.provisioning.storage;\n\
        \x20 }};\n\
         }}\n",
        store_view = super::stock::nix_string(store_view_json),
    )
}

fn resolve_authorized_input(source: AuthorizedInputSource) -> Result<AuthorizedProvisioningInput> {
    match source {
        AuthorizedInputSource::DirectResult { input } => Ok(input),
        AuthorizedInputSource::RetainedArtifact {
            artifact,
            content_sha256,
        } => {
            let path = Path::new(&artifact.store_path);
            ensure!(
                path.is_absolute()
                    && path.parent() == Some(Path::new("/nix/store"))
                    && path.components().all(|component| matches!(
                        component,
                        Component::RootDir | Component::Normal(_)
                    )),
                "authorized-input artifact is not an exact Nix store object"
            );
            let metadata = fs::symlink_metadata(path)
                .context("inspecting the retained authorized-input artifact")?;
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "authorized-input artifact is not a regular immutable object"
            );
            ensure!(
                metadata.len() <= ABILITY_LIMITS_V1.max_document_bytes,
                "authorized-input artifact exceeds the canonical document bound"
            );
            ensure!(
                fs::canonicalize(path)? == path,
                "authorized-input artifact path is not canonical"
            );
            let bytes = fs::read(path).context("reading the retained authorized-input artifact")?;
            ensure!(
                Sha256Digest::of_bytes(&bytes) == content_sha256,
                "authorized-input artifact differs from its observed content digest"
            );
            aos_contract::canonical::from_slice(&bytes, "retained authorized provisioning input")
        }
    }
}

fn prepare_host_input(root: &Path, input: &AuthorizedProvisioningInput) -> Result<PathBuf> {
    let path = root.join("host.nix");
    let bytes = match input.host_module.as_deref() {
        Some(module) => module.as_bytes(),
        None => b"{}\n",
    };
    fs::write(&path, bytes).context("writing private authorized host input")?;
    Ok(path)
}

fn prepare_facts_input(root: &Path, input: &AuthorizedProvisioningInput) -> Result<PathBuf> {
    let path = root.join("facts.json");
    let bytes = aos_contract::canonical::to_vec(&input.facts.value)
        .context("encoding canonical observational instance facts")?;
    fs::write(&path, bytes).context("writing private observational facts input")?;
    Ok(path)
}

fn read_module_abi(base_lib: &Path) -> Result<u32> {
    let value = fs::read_to_string(base_lib.join("module-abi"))
        .context("reading immutable base-library module ABI")?;
    value
        .trim()
        .parse()
        .context("parsing immutable base-library module ABI")
}

fn retained_inputs(
    input: &AuthorizedProvisioningInput,
    host_nix: &Path,
    facts_json: &Path,
) -> Result<RetainedHostInputs> {
    let host_bytes = fs::read(host_nix).context("reading pinned authorized host input")?;
    let facts_bytes = fs::read(facts_json).context("reading pinned observational facts")?;
    let facts: aos_metadata::fetcher::Facts =
        serde_json::from_slice(&facts_bytes).context("decoding observational instance facts")?;
    ensure!(
        aos_metadata::facts_render::canonicalize_host_facts(&facts)? == facts,
        "authorized observational instance facts are not canonical"
    );
    let normalized = aos_metadata::facts_render::normalize_host_facts(&facts);
    let normalized = serde_json::to_vec(&normalized)
        .context("encoding normalized observational instance facts")?;
    let (host_trust_mode, host_platform, host_signer) = match input.source {
        CanonicalProvisioningSource::Fallback => ("image", "image".into(), None),
        CanonicalProvisioningSource::Operator => {
            let trust_mode = match input.authorization.trust_mode {
                ProvisioningTrustMode::Platform => "platform",
                ProvisioningTrustMode::Signed => "signed",
            };
            (
                trust_mode,
                input.authorization.platform_id.clone(),
                input.authorization.signer.clone(),
            )
        }
    };

    Ok(RetainedHostInputs {
        host_nix: HostNixInput {
            content_hash: sha256_identity(&host_bytes),
            trust_mode: host_trust_mode.into(),
            platform: host_platform,
            signer_key: host_signer,
            store_path: host_nix.to_string_lossy().into_owned(),
        },
        instance_facts: InstanceFactsInput {
            facts_hash: sha256_identity(&normalized),
            platform: input.authorization.platform_id.clone(),
            store_path: facts_json.to_string_lossy().into_owned(),
        },
    })
}

fn marker_uuid_for_source(
    marker: &ProvisioningMarkerObservation,
    source: CanonicalProvisioningSource,
) -> Result<String> {
    validate_provisioning_marker_observation(marker)?;
    match marker.state {
        ProvisioningMarkerState::Absent => Ok(generate_marker_uuid()),
        ProvisioningMarkerState::Completed => {
            let committed = marker.source.context("completed marker has no source")?;
            ensure!(
                committed == source,
                "current storage source differs from the committed provisioning source"
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
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioning_uses_one_complete_initrd_fixed_point() {
        let expression = complete_initrd_expression(
            "<base>",
            "<host>",
            "{}",
            r#"{"schema":"aos.package-store.read-view-locator/v1"}"#,
        );

        assert!(expression.contains("evalCompleteInitrdConfig"));
        for forbidden in ["evalProvisioningConfig", "evalHostSelection", "evalHostConfig"] {
            assert!(!expression.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn completed_marker_must_match_authorized_source() {
        let marker = ProvisioningMarkerObservation {
            schema: "aos.storage.provisioning-marker-observation/v1".into(),
            state: ProvisioningMarkerState::Completed,
            source: Some(CanonicalProvisioningSource::Operator),
            marker_uuid: Some("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".into()),
        };

        assert!(marker_uuid_for_source(&marker, CanonicalProvisioningSource::Fallback).is_err());
        assert_eq!(
            marker_uuid_for_source(&marker, CanonicalProvisioningSource::Operator)
                .expect("matching committed marker"),
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        );
    }
}
