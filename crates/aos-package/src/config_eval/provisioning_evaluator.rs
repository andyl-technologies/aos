//! Full configuration evaluation for the durable provisioning controller.
//!
//! The evaluator consumes only the protected authorization result and the
//! synchronized registry snapshot carried by checked result edges. Mutable
//! registry locations remain implementation details: their authenticated
//! release receipts and immutable image contract must match the snapshot before
//! the same loaded resolver participates in the module fixed point.

use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::{
    ABILITY_LIMITS_V1, ArtifactReference, LocalKey, MAX_TRANSACTION_BLOB_BYTES, ResourceReference,
};
use aos_contract::Sha256Digest;
use aos_provider_protocol::{TRANSACTION_BLOB_OUTPUT_TYPE, TransactionBlobOutput};
use aos_storage_provisioning::{
    AuthorizedProvisioningInput, CanonicalProvisioningSource, ProvisioningIntent,
    ProvisioningTrustMode, validate_authorized_provisioning_input, validate_provisioning_intent,
};
use serde::Deserialize;
use tempfile::Builder;

use super::materialize::{ConfigManifest, HostNixInput, InstanceFactsInput};
use super::registry_snapshot_provider::{SynchronizedSnapshot, validate_synchronized_snapshot};
use super::{
    EvalCommand, RetainedHostInputs, add_fixed_eval_host_source, add_fixed_input_to_store,
    read_base_lib_abi_hash, run_eval_command, sha256_identity,
};

const RESULT_SCHEMA: &str = "aos.configuration.provisioning-evaluation-result/v1";
pub(crate) const MANIFEST_SLOT: &str = "configuration-manifest";

/// Carries one checked evaluator invocation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvaluationParameters {
    /// Carries the durable storage-provisioning intent.
    pub(crate) request: ProvisioningIntent,
    /// Carries the only value authorized to supply host configuration bytes.
    pub(crate) authorized_input: AuthorizedInputSource,
    /// Pins the synchronized registry and immutable image authorities.
    pub(crate) registry_snapshot: SynchronizedSnapshot,
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

/// Carries canonical manifest bytes and their graph-bound result envelope.
pub(crate) struct EvaluationOutput {
    /// Exact canonical configuration manifest bytes.
    pub(crate) manifest: Vec<u8>,
    /// Small typed result returned after the blob transport publishes bytes.
    pub(crate) result: EvaluationResult,
}

/// Carries the non-path identity of one completed provisioning evaluation.
#[derive(Debug, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvaluationResult {
    /// Carries [`RESULT_SCHEMA`].
    pub(crate) schema: &'static str,
    /// Repeats the controller identity authenticated by the snapshot.
    pub(crate) controller: ResourceReference,
    /// Repeats the stage handoff authenticated by the snapshot.
    pub(crate) handoff: ResourceReference,
    /// Requests runtime publication of the canonical manifest byte slot.
    pub(crate) manifest_blob: TransactionBlobOutput,
    /// Authenticates the exact canonical manifest bytes.
    pub(crate) manifest_sha256: Sha256Digest,
    /// Binds evaluation to the synchronized registry commitment.
    pub(crate) registry_snapshot_sha256: String,
    /// Authenticates operator host bytes when the operator arm is selected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) host_module_sha256: Option<String>,
    /// Retains the explicitly observational facts commitment.
    pub(crate) instance_facts_sha256: String,
}

/// Evaluates one authorized provisioning input into canonical manifest bytes.
///
/// # Errors
///
/// Returns an error when authorization or snapshot commitments are invalid,
/// immutable base-library identity differs, the authenticated package-module
/// fixed point fails, or the canonical manifest exceeds the transaction blob
/// transport bound.
pub(crate) fn evaluate(parameters: EvaluationParameters) -> Result<EvaluationOutput> {
    validate_provisioning_intent(&parameters.request)?;
    validate_synchronized_snapshot(&parameters.registry_snapshot)?;
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
    let module_abi = read_module_abi(&base_lib)?;
    let abi_hash = read_base_lib_abi_hash(&base_lib, module_abi)?;
    ensure!(
        abi_hash == authorized_input.base_library.abi_hash,
        "authorized base-library ABI differs from the immutable module library"
    );
    let retained = retained_inputs(&authorized_input, &pinned_host, &pinned_facts)?;
    let out = scratch.path().join("manifest.json");
    run_eval_command(&EvalCommand {
        host_nix: pinned_host,
        runtime_modules: Vec::new(),
        runtime_module_root: None,
        expected_current_generation: None,
        base_lib,
        facts_json: Some(pinned_facts),
        desired: None,
        module_abi,
        out: out.clone(),
        eval_root,
        verbose: 0,
        trusted_config_keys_dirs: Vec::new(),
        retained_host_inputs: Some(retained),
        require_signed_host_nix: false,
        image_default_host: authorized_input.source == CanonicalProvisioningSource::Fallback,
        registry_snapshot: Some(parameters.registry_snapshot.clone()),
    })?;

    let manifest = canonical_manifest(&out)?;
    ensure!(
        manifest.len() as u64 <= MAX_TRANSACTION_BLOB_BYTES,
        "canonical configuration manifest exceeds the transaction blob bound"
    );
    let manifest_sha256 = Sha256Digest::of_bytes(&manifest);
    let result = EvaluationResult {
        schema: RESULT_SCHEMA,
        controller: parameters.registry_snapshot.controller,
        handoff: parameters.registry_snapshot.handoff,
        manifest_blob: TransactionBlobOutput {
            kind: TRANSACTION_BLOB_OUTPUT_TYPE.into(),
            slot: LocalKey::new(MANIFEST_SLOT)?,
        },
        manifest_sha256,
        registry_snapshot_sha256: parameters.registry_snapshot.snapshot_sha256,
        host_module_sha256: authorized_input.host_module_sha256,
        instance_facts_sha256: authorized_input.facts.sha256,
    };
    Ok(EvaluationOutput { manifest, result })
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

fn canonical_manifest(path: &Path) -> Result<Vec<u8>> {
    let bytes = fs::read(path).context("reading evaluated configuration manifest")?;
    let manifest: ConfigManifest =
        serde_json::from_slice(&bytes).context("decoding evaluated configuration manifest")?;
    manifest.validate()?;
    aos_contract::canonical::to_vec(&manifest).context("encoding canonical configuration manifest")
}
