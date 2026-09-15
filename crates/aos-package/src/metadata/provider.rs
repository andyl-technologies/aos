//! Ability handler for authenticated provisioning metadata and plan evaluation.
//!
//! The handler keeps acquisition scratch private to one invocation. Exact host
//! bytes cross into plan evaluation only through the protected runtime output;
//! no path below the metadata stash is a cross-provider data channel.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, ArtifactReference, LocalKey, ResourceReference,
};
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, HANDLER_ABI_ARGUMENT, INVOCATION_SCHEMA, Invocation,
    InvocationDisposition, InvocationPurpose, InvocationResult, RESULT_SCHEMA, ResourceContext,
    SupportedPurposes, resource_set_digest, validate_admission_resource, validate_resource_context,
    validate_resource_contexts,
};
use aos_storage_provisioning::{
    AuthorizedProvisioningInput, BaseLibraryIdentity, CanonicalProvisioningPlan,
    CanonicalProvisioningSource, ProvisioningAuthorization, ProvisioningIntent,
    ProvisioningTrustMode, validate_authorized_provisioning_input, validate_provisioning_intent,
};
use serde::{Deserialize, Serialize};
use tempfile::Builder;

use super::detect::{DetectOptions, run_detect};
use super::mount::BlkidProbe;
use super::provisioning::{
    AuthorizeOptions, EvalProvisioningOptions, ProvisioningSource, ProvisioningTrust,
    evaluate_canonical_provisioning_plan, run_authorize,
};
use super::{FetchOptions, run_fetch};

const AUTHORIZATION_INTERFACE: &str = "aos.metadata.storage-provisioning-input-authorization";
const PLAN_INTERFACE: &str = "aos.metadata.storage-provisioning-plan";
const AUTHORIZATION_OBSERVATION: &str = "aos.metadata.provisioning-authorization-observation/v1";
const PLAN_OBSERVATION: &str = "aos.metadata.provisioning-plan-observation/v1";
const PROVIDER_CONTEXT: &str = "aos.metadata.provisioning-provider-context/v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationParameters {
    request: ProvisioningIntent,
    configuration: AuthorizationConfiguration,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationConfiguration {
    schema: String,
    trust_mode: ProvisioningTrustMode,
    trusted_config_keys: Vec<TrustedKeyFile>,
    base_library: BaseLibraryIdentity,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum TrustedKeyFile {
    ArtifactFile {
        reference: ArtifactPathReference,
    },
    ImmutableFile {
        path: String,
        content_sha256: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactPathReference {
    artifact: ArtifactReference,
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanParameters {
    request: ProvisioningIntent,
    authorized_input: AuthorizedProvisioningInput,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderContext {
    schema: &'static str,
    interface: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationObservation {
    schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<CanonicalProvisioningSource>,
    state: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct PlanObservation {
    schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<CanonicalProvisioningSource>,
    state: &'static str,
}

/// Runs one metadata provisioning handler call from the process streams.
///
/// # Errors
///
/// Returns an error when the selected ABI, checked authority, metadata input,
/// restricted evaluation, or provider result is invalid.
pub async fn run_provider_from_process() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    ensure!(
        arguments.len() == 2 && arguments[0] == HANDLER_ABI_ARGUMENT,
        "expected --aos-primitive-v1 and one purpose"
    );

    let mut input = Vec::new();
    io::stdin()
        .take(ABILITY_LIMITS_V1.max_document_bytes + 1)
        .read_to_end(&mut input)?;
    ensure!(
        input.len() as u64 <= ABILITY_LIMITS_V1.max_document_bytes,
        "protocol input exceeds the canonical document bound"
    );

    let value = match arguments[1].as_str() {
        "admit" => {
            let request = aos_contract::canonical::from_slice(&input, "metadata admission")?;
            serde_json::to_value(admit(request)?)?
        }
        "effect" | "reconcile" | "cancel" => {
            let invocation = aos_contract::canonical::from_slice(&input, "metadata invocation")?;
            serde_json::to_value(invoke(invocation, &arguments[1]).await?)?
        }
        purpose => bail!("unsupported metadata provider purpose {purpose:?}"),
    };
    let output = aos_contract::canonical::canonical_json(&value)?;
    ensure!(
        output.len() <= aos_provider_protocol::MAX_HANDLER_RESULT_BYTES,
        "metadata provider result exceeds the handler bound"
    );
    io::stdout().write_all(&output)?;
    Ok(())
}

fn admit(request: AdmissionRequest) -> Result<AdmissionResult> {
    ensure!(
        request.schema == ADMISSION_REQUEST_SCHEMA,
        "unsupported admission schema"
    );
    validate_admission_resource(&request)?;
    validate_resource_contexts(&request.resources)?;
    let interface = request.method.interface.name.as_str();
    validate_method(interface, request.method.method.as_str())?;
    let intent: ProvisioningIntent = decode(&request.resource_spec.value)?;
    validate_provisioning_intent(&intent)?;

    let observation = match interface {
        AUTHORIZATION_INTERFACE => authorization_observation(None, "ready")?,
        PLAN_INTERFACE => plan_observation(None, "ready")?,
        _ => bail!("unsupported metadata provisioning interface"),
    };
    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.into(),
        disposition: AdmissionDisposition::Admitted,
        revision: AdmissionRevision::Absent,
        incarnation: Some(request.assignment.incarnation),
        observation,
        native_context: ability_value(serde_json::to_value(ProviderContext {
            schema: PROVIDER_CONTEXT,
            interface: interface.into(),
        })?)?,
        supported_purposes: SupportedPurposes::from_ordered(vec![
            InvocationPurpose::Effect,
            InvocationPurpose::Reconcile,
            InvocationPurpose::Cancel,
        ])
        .context("constructing metadata provider purpose set")?,
    })
}

async fn invoke(invocation: Invocation, purpose: &str) -> Result<InvocationResult> {
    ensure!(
        invocation.schema == INVOCATION_SCHEMA && purpose == purpose_name(invocation.purpose),
        "invocation envelope differs from the selected ABI"
    );
    ensure!(
        invocation.method_is_bound(),
        "invocation method is not durably bound"
    );
    validate_resource_contexts(&invocation.request.resources)?;
    ensure!(
        resource_set_digest(&invocation.request.resources)?
            == invocation.request.native_context_digest,
        "resource contexts differ from their authenticated digest"
    );
    let interface = invocation.method.interface.name.as_str();
    validate_method(interface, invocation.method.method.as_str())?;
    let target = exact_context(&invocation.request.target, &invocation.request.resources)?;
    let bound = validate_resource_context(target)?;
    let intent: ProvisioningIntent = decode(&bound.resource_spec.value)?;
    validate_provisioning_intent(&intent)?;

    if invocation.control.cancelled || invocation.purpose == InvocationPurpose::Cancel {
        return cancelled_result(&invocation, interface);
    }
    ensure!(
        matches!(
            invocation.purpose,
            InvocationPurpose::Effect | InvocationPurpose::Reconcile
        ),
        "metadata provisioning does not support compensation"
    );

    match interface {
        AUTHORIZATION_INTERFACE => {
            let parameters: AuthorizationParameters = decode(&invocation.request.inputs)?;
            ensure!(
                parameters.request == intent,
                "authorization request differs from the checked resource"
            );
            let authorized = authorize(&parameters.configuration).await?;
            let evidence = authorization_observation(Some(authorized.source), "authorized")?;
            completed_result(
                &invocation,
                evidence,
                "authorized-provisioning-input",
                ability_value(serde_json::to_value(authorized)?)?,
            )
        }
        PLAN_INTERFACE => {
            let parameters: PlanParameters = decode(&invocation.request.inputs)?;
            ensure!(
                parameters.request == intent,
                "plan request differs from the checked resource"
            );
            let source = parameters.authorized_input.source;
            let lsblk = required_tool("AOS_METADATA_LSBLK")?;
            let nix_instantiate = required_tool("AOS_METADATA_NIX_INSTANTIATE")?;
            let plan = observe_plan(
                &parameters.request,
                &parameters.authorized_input,
                &lsblk,
                &nix_instantiate,
            )?;
            completed_result(
                &invocation,
                plan_observation(Some(source), "planned")?,
                "provisioning-plan",
                ability_value(serde_json::to_value(plan)?)?,
            )
        }
        _ => bail!("unsupported metadata provisioning interface"),
    }
}

async fn authorize(
    configuration: &AuthorizationConfiguration,
) -> Result<AuthorizedProvisioningInput> {
    validate_authorization_configuration(&configuration)?;
    let scratch = Builder::new()
        .prefix("aos-metadata-provisioning-")
        .tempdir()?;
    let stash_dir = scratch.path().join("stash");
    let media_mountpoint = scratch.path().join("media");
    run_detect(
        &DetectOptions {
            sysfs_root: PathBuf::from("/"),
            stash_dir: stash_dir.clone(),
            media_mountpoint,
        },
        &BlkidProbe::with_tools(
            required_tool("AOS_METADATA_BLKID")?,
            required_tool("AOS_METADATA_MOUNT")?,
        ),
    )?;
    run_fetch(&FetchOptions {
        stash_dir: stash_dir.clone(),
        var_etc_root: None,
    })
    .await?;

    let trusted_key_files = trusted_key_files(&configuration.trusted_config_keys)?;
    let trusted_key_dir = scratch.path().join("trusted-config-keys");
    materialize_trusted_keys(&trusted_key_files, &trusted_key_dir)?;
    let trust = match configuration.trust_mode {
        ProvisioningTrustMode::Platform => ProvisioningTrust::Platform,
        ProvisioningTrustMode::Signed => ProvisioningTrust::Signed,
    };
    let result = run_authorize(&AuthorizeOptions {
        stash_dir: stash_dir.clone(),
        trust,
        trusted_config_key_dirs: vec![trusted_key_dir],
    })?;
    let platform_id = super::Stash::open(&stash_dir)?
        .read_platform_env()?
        .platform_id;
    let input = match result {
        Some(result) => {
            let host_module = fs::read_to_string(stash_dir.join("host.nix"))
                .context("reading exact authorized host module")?;
            AuthorizedProvisioningInput {
                schema: "aos.metadata.authorized-provisioning-input/v1".into(),
                source: CanonicalProvisioningSource::Operator,
                host_module: Some(host_module),
                host_module_sha256: Some(format!("sha256:{}", result.host_nix_sha256)),
                authorization: ProvisioningAuthorization {
                    trust_mode: configuration.trust_mode,
                    platform_id,
                    signer: result.signer,
                },
                base_library: configuration.base_library.clone(),
            }
        }
        None => AuthorizedProvisioningInput {
            schema: "aos.metadata.authorized-provisioning-input/v1".into(),
            source: CanonicalProvisioningSource::Fallback,
            host_module: None,
            host_module_sha256: None,
            authorization: ProvisioningAuthorization {
                trust_mode: configuration.trust_mode,
                platform_id,
                signer: None,
            },
            base_library: configuration.base_library.clone(),
        },
    };
    validate_authorized_provisioning_input(&input)?;
    Ok(input)
}

fn observe_plan(
    request: &ProvisioningIntent,
    input: &AuthorizedProvisioningInput,
    lsblk: &Path,
    nix_instantiate: &Path,
) -> Result<CanonicalProvisioningPlan> {
    validate_authorized_provisioning_input(input)?;
    verify_base_library(&input.base_library)?;
    let scratch = Builder::new().prefix("aos-provisioning-plan-").tempdir()?;
    let stash_dir = scratch.path().join("input");
    fs::create_dir_all(&stash_dir)?;
    if let Some(module) = &input.host_module {
        fs::write(stash_dir.join("host.nix"), module)?;
    }
    let (committed_source, marker_uuid) = observed_marker(lsblk)?;
    evaluate_canonical_provisioning_plan(&EvalProvisioningOptions {
        stash_dir,
        base_lib: PathBuf::from(&input.base_library.store_path),
        eval_root: scratch.path().join("eval"),
        measured_boot: request.measured_boot,
        committed_source,
        marker_uuid,
        nix_instantiate: nix_instantiate.to_path_buf(),
    })
}

fn validate_authorization_configuration(configuration: &AuthorizationConfiguration) -> Result<()> {
    ensure!(
        configuration.schema == "aos.metadata.provisioning-authorization-configuration/v1",
        "unsupported provisioning authorization configuration"
    );
    ensure!(
        configuration.trusted_config_keys.len() <= 64,
        "trusted configuration keys exceed the interface bound"
    );
    if configuration.trust_mode == ProvisioningTrustMode::Signed {
        ensure!(
            !configuration.trusted_config_keys.is_empty(),
            "signed provisioning requires a trusted configuration key"
        );
    }
    trusted_key_files(&configuration.trusted_config_keys)?;
    verify_base_library(&configuration.base_library)
}

fn trusted_key_files(files: &[TrustedKeyFile]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for file in files {
        let path = match file {
            TrustedKeyFile::ArtifactFile { reference } => artifact_file(reference)?,
            TrustedKeyFile::ImmutableFile {
                path,
                content_sha256,
            } => {
                ensure!(
                    path.starts_with("/nix/store/"),
                    "trusted configuration key is not immutable"
                );
                let bytes = fs::read(path)?;
                ensure!(
                    digest(&bytes) == *content_sha256,
                    "trusted configuration key differs from its content digest"
                );
                PathBuf::from(path)
            }
        };
        ensure!(
            path.is_file(),
            "trusted configuration key is not a regular file"
        );
        if !paths.iter().any(|existing| existing == &path) {
            paths.push(path);
        }
    }
    Ok(paths)
}

fn materialize_trusted_keys(files: &[PathBuf], directory: &Path) -> Result<()> {
    fs::create_dir_all(directory)?;
    let mut names = std::collections::BTreeSet::new();
    for source in files {
        let name = source
            .file_name()
            .and_then(|name| name.to_str())
            .context("trusted configuration key has no UTF-8 file name")?;
        ensure!(
            name.ends_with(".pub") && name.len() > 4,
            "trusted configuration key must use an operator .pub file name"
        );
        ensure!(
            names.insert(name.to_string()),
            "trusted configuration key names collide"
        );
        fs::copy(source, directory.join(name))?;
    }
    Ok(())
}

fn artifact_file(reference: &ArtifactPathReference) -> Result<PathBuf> {
    let relative = Path::new(&reference.path);
    ensure!(
        !relative.is_absolute()
            && relative
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "trusted configuration key artifact path is not strict relative"
    );
    let root = fs::canonicalize(&reference.artifact.store_path)?;
    let path = fs::canonicalize(root.join(relative))?;
    ensure!(
        path.starts_with(&root),
        "trusted configuration key escapes its artifact"
    );
    Ok(path)
}

fn verify_base_library(identity: &BaseLibraryIdentity) -> Result<()> {
    ensure!(
        identity.store_path.starts_with("/nix/store/"),
        "base library is not an immutable store path"
    );
    let actual = fs::read_to_string(Path::new(&identity.store_path).join("abi-hash"))?;
    ensure!(
        actual.trim() == identity.abi_hash,
        "base-library ABI hash differs from the fixed-point identity"
    );
    Ok(())
}

fn required_tool(variable: &str) -> Result<PathBuf> {
    let value = std::env::var_os(variable)
        .with_context(|| format!("reading authenticated handler tool {variable}"))?;
    let path = PathBuf::from(value);
    ensure!(
        path.is_absolute() && path.starts_with("/nix/store/"),
        "authenticated handler tool {variable} is outside the immutable store"
    );
    let canonical = fs::canonicalize(&path)
        .with_context(|| format!("resolving authenticated handler tool {variable}"))?;
    ensure!(
        canonical.is_file(),
        "authenticated handler tool {variable} is not a file"
    );
    Ok(canonical)
}

fn observed_marker(lsblk: &Path) -> Result<(Option<ProvisioningSource>, Option<String>)> {
    let markers = [
        ("aos-provenance-operator-v1", ProvisioningSource::Operator),
        ("aos-provenance-fallback-v1", ProvisioningSource::Fallback),
    ]
    .into_iter()
    .filter(|(label, _)| Path::new("/dev/disk/by-partlabel").join(label).exists())
    .collect::<Vec<_>>();
    ensure!(
        markers.len() <= 1,
        "several durable provisioning markers exist"
    );
    if Path::new("/dev/disk/by-partlabel/aos-provisioning-pending-v1").exists() {
        bail!("pending provisioning marker requires explicit recovery");
    }
    let Some((label, source)) = markers.first().copied() else {
        return Ok((None, None));
    };
    let path = Path::new("/dev/disk/by-partlabel").join(label);
    let output = Command::new(lsblk)
        .args(["-ndo", "PARTUUID"])
        .arg(path)
        .output()
        .context("observing durable provisioning marker UUID")?;
    ensure!(
        output.status.success(),
        "lsblk could not observe the provisioning marker UUID"
    );
    let uuid = String::from_utf8(output.stdout)?.trim().to_string();
    ensure!(
        !uuid.is_empty(),
        "durable provisioning marker has no PARTUUID"
    );
    Ok((Some(source), Some(uuid)))
}

fn validate_method(interface: &str, method: &str) -> Result<()> {
    match (interface, method) {
        (AUTHORIZATION_INTERFACE, "authorize") | (PLAN_INTERFACE, "observe") => Ok(()),
        _ => bail!("unsupported metadata provisioning method"),
    }
}

fn exact_context<'a>(
    reference: &ResourceReference,
    resources: &'a [ResourceContext],
) -> Result<&'a ResourceContext> {
    let matches = resources
        .iter()
        .filter(|context| context.reference == *reference)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "resource reference has no unique runtime context"
    );
    Ok(matches[0])
}

fn authorization_observation(
    source: Option<CanonicalProvisioningSource>,
    state: &'static str,
) -> Result<AbilityValue> {
    ability_value(serde_json::to_value(AuthorizationObservation {
        schema: AUTHORIZATION_OBSERVATION,
        source,
        state,
    })?)
}

fn plan_observation(
    source: Option<CanonicalProvisioningSource>,
    state: &'static str,
) -> Result<AbilityValue> {
    ability_value(serde_json::to_value(PlanObservation {
        schema: PLAN_OBSERVATION,
        source,
        state,
    })?)
}

fn completed_result(
    invocation: &Invocation,
    evidence: AbilityValue,
    output_name: &str,
    output: AbilityValue,
) -> Result<InvocationResult> {
    let mut outputs = BTreeMap::new();
    outputs.insert(LocalKey::new(output_name)?, output);
    Ok(InvocationResult {
        schema: RESULT_SCHEMA.into(),
        disposition: InvocationDisposition::Completed,
        evidence,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

fn cancelled_result(invocation: &Invocation, interface: &str) -> Result<InvocationResult> {
    let evidence = match interface {
        AUTHORIZATION_INTERFACE => authorization_observation(None, "ready")?,
        PLAN_INTERFACE => plan_observation(None, "ready")?,
        _ => bail!("unsupported metadata provisioning interface"),
    };
    Ok(InvocationResult {
        schema: RESULT_SCHEMA.into(),
        disposition: InvocationDisposition::RejectedBeforeEffect,
        evidence,
        outputs: BTreeMap::new(),
        native_context_digest: invocation.request.native_context_digest,
    })
}

fn ability_value(value: serde_json::Value) -> Result<AbilityValue> {
    AbilityValue::new(value).map_err(anyhow::Error::msg)
}

fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};

    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn decode<T: serde::de::DeserializeOwned>(value: &AbilityValue) -> Result<T> {
    serde_json::from_value(value.as_json().clone()).map_err(anyhow::Error::from)
}

fn purpose_name(purpose: InvocationPurpose) -> &'static str {
    match purpose {
        InvocationPurpose::Effect => "effect",
        InvocationPurpose::Reconcile => "reconcile",
        InvocationPurpose::Cancel => "cancel",
        InvocationPurpose::Compensate => "compensate",
        InvocationPurpose::ReconcileCompensation => "reconcile-compensation",
    }
}
