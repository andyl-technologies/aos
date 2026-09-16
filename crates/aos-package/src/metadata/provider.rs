//! Ability handler for provisioning metadata and configuration evaluation.
//!
//! The handler keeps acquisition scratch private to one invocation. Exact host
//! bytes and semantic early-network facts cross into later operations only
//! through protected typed outputs. No path below the metadata stash is a
//! cross-provider data channel.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, ArtifactReference, LocalKey, MethodReference,
    ResourceReference,
};
use aos_net::{BootstrapLinkSelector, BootstrapNetwork};
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, HANDLER_ABI_ARGUMENT, INVOCATION_SCHEMA, Invocation,
    InvocationDisposition, InvocationPurpose, InvocationResult, RESULT_SCHEMA, ResourceContext,
    SupportedPurposes, TRANSACTION_BLOB_OUTPUT_DIRECTORY_ENV, TRANSACTION_BLOB_OUTPUT_TYPE,
    TransactionBlobOutput, resource_set_digest, validate_admission_resource,
    validate_resource_context, validate_resource_contexts,
};
use aos_storage_provisioning::{
    AuthorizedProvisioningInput, BaseLibraryIdentity, CanonicalProvisioningPlan,
    CanonicalProvisioningSource, ProvisioningAuthorization, ProvisioningIntent,
    ProvisioningMarkerObservation, ProvisioningTrustMode, observed_instance_facts,
    validate_authorized_provisioning_input, validate_provisioning_intent,
};
use serde::{Deserialize, Serialize};
use tempfile::Builder;

use super::detect::{detect, needs_network, platform_capability};
use super::mount::BlkidProbe;
use super::provisioning::{
    AuthorizeOptions, EvalProvisioningOptions, ProvisioningTrust,
    evaluate_canonical_provisioning_plan, run_authorize,
};
use super::{FetchOptions, run_fetch};
use crate::config_eval::provisioning_evaluator::{self, EvaluationParameters, MANIFEST_SLOT};

const AUTHORIZATION_OBSERVATION: &str = "aos.metadata.provisioning-authorization-observation/v1";
const DETECTION_OBSERVATION: &str = "aos.metadata.provisioning-platform-observation/v1";
const PLAN_OBSERVATION: &str = "aos.metadata.provisioning-plan-observation/v1";
const EVALUATION_OBSERVATION: &str = "aos.configuration.provisioning-evaluation-observation/v1";
const PROVIDER_CONTEXT: &str = "aos.metadata.provisioning-provider-context/v1";
const AUTHORIZED_INPUT_SLOT: &str = "authorized-provisioning-input";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum MetadataRole {
    Authorization,
    ConfigurationEvaluation,
    PlanObservation,
    PlatformDetection,
}

impl MetadataRole {
    fn from_method(method: &MethodReference) -> Result<Self> {
        match (method.interface.name.as_str(), method.method.as_str()) {
            ("aos.metadata.storage-provisioning-input-authorization", "authorize") => {
                Ok(Self::Authorization)
            }
            ("aos.configuration.storage-provisioning-evaluation", "evaluate") => {
                Ok(Self::ConfigurationEvaluation)
            }
            ("aos.metadata.storage-provisioning-plan", "observe") => Ok(Self::PlanObservation),
            ("aos.metadata.storage-provisioning-platform-detection", "detect") => {
                Ok(Self::PlatformDetection)
            }
            _ => bail!("interface method does not select a checked metadata handler role"),
        }
    }

    const fn method(self) -> &'static str {
        match self {
            Self::Authorization => "authorize",
            Self::ConfigurationEvaluation => "evaluate",
            Self::PlanObservation => "observe",
            Self::PlatformDetection => "detect",
        }
    }

    fn initial_observation(self) -> Result<AbilityValue> {
        match self {
            Self::Authorization => authorization_observation(None, "ready"),
            Self::ConfigurationEvaluation => evaluation_observation(None, "ready"),
            Self::PlanObservation => plan_observation(None, "ready"),
            Self::PlatformDetection => detection_observation(None, "ready"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationParameters {
    request: ProvisioningIntent,
    configuration: AuthorizationConfiguration,
    platform: DetectedPlatform,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetectionParameters {
    request: ProvisioningIntent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DetectedPlatform {
    schema: String,
    platform_id: String,
    need_network: bool,
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
    marker: ProvisioningMarkerObservation,
}

#[derive(Debug)]
struct AuthorizationOutputs {
    authorized_input: AuthorizedProvisioningInput,
    network_bootstrap: Option<AbilityValue>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderContext {
    schema: String,
    role: MetadataRole,
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
struct DetectionObservation {
    schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    platform_id: Option<String>,
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

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct EvaluationObservation {
    schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_sha256: Option<String>,
    state: &'static str,
}

/// Runs one metadata provisioning handler call from the process streams.
///
/// # Errors
///
/// Returns an error when the selected ABI, checked authority, metadata input,
/// restricted evaluation, or provider result is invalid.
pub async fn run_provider_from_process() -> Result<()> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    ensure!(
        arguments.len() == 3 && arguments[1] == HANDLER_ABI_ARGUMENT,
        "expected --aos-primitive-v1 and one purpose"
    );
    let purpose = arguments[2]
        .to_str()
        .context("metadata handler purpose is not valid UTF-8")?;

    let mut input = Vec::new();
    io::stdin()
        .take(ABILITY_LIMITS_V1.max_document_bytes + 1)
        .read_to_end(&mut input)?;
    ensure!(
        input.len() as u64 <= ABILITY_LIMITS_V1.max_document_bytes,
        "protocol input exceeds the canonical document bound"
    );

    let value = match purpose {
        "admit" => {
            let request: AdmissionRequest =
                aos_contract::canonical::from_slice(&input, "metadata admission")?;
            let role = MetadataRole::from_method(&request.method)?;
            serde_json::to_value(admit(role, request)?)?
        }
        "effect" | "reconcile" | "cancel" => {
            let invocation: Invocation =
                aos_contract::canonical::from_slice(&input, "metadata invocation")?;
            let role = MetadataRole::from_method(&invocation.method)?;
            serde_json::to_value(invoke(role, invocation, purpose).await?)?
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

fn admit(role: MetadataRole, request: AdmissionRequest) -> Result<AdmissionResult> {
    ensure!(
        request.schema == ADMISSION_REQUEST_SCHEMA,
        "unsupported admission schema"
    );
    validate_admission_resource(&request)?;
    validate_resource_contexts(&request.resources)?;
    validate_method(role, request.method.method.as_str())?;
    let intent: ProvisioningIntent = decode(&request.resource_spec.value)?;
    validate_provisioning_intent(&intent)?;

    let observation = role.initial_observation()?;
    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.into(),
        disposition: AdmissionDisposition::Admitted,
        revision: AdmissionRevision::Absent,
        incarnation: Some(request.assignment.incarnation),
        observation,
        native_context: ability_value(serde_json::to_value(ProviderContext {
            schema: PROVIDER_CONTEXT.into(),
            role,
        })?)?,
        supported_purposes: SupportedPurposes::from_ordered(vec![
            InvocationPurpose::Effect,
            InvocationPurpose::Reconcile,
            InvocationPurpose::Cancel,
        ])
        .context("constructing metadata provider purpose set")?,
    })
}

async fn invoke(
    role: MetadataRole,
    invocation: Invocation,
    purpose: &str,
) -> Result<InvocationResult> {
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
    validate_method(role, invocation.method.method.as_str())?;
    validate_method(role, invocation.request.method.method.as_str())?;
    let target = exact_context(&invocation.request.target, &invocation.request.resources)?;
    let bound = validate_resource_context(target)?;
    ensure!(
        invocation.method.interface == invocation.request.method.interface
            && invocation.method.interface == invocation.request.target.interface
            && invocation
                .request
                .target
                .operations
                .binary_search(&invocation.method.method)
                .is_ok(),
        "invocation method differs from the checked target interface"
    );
    let provider_context: ProviderContext = decode(&bound.provider_context)?;
    ensure!(
        provider_context.schema == PROVIDER_CONTEXT && provider_context.role == role,
        "metadata provider context differs from the selected handler role"
    );
    let intent: ProvisioningIntent = decode(&bound.resource_spec.value)?;
    validate_provisioning_intent(&intent)?;

    if invocation.control.cancelled || invocation.purpose == InvocationPurpose::Cancel {
        return cancelled_result(&invocation, role);
    }
    ensure!(
        matches!(
            invocation.purpose,
            InvocationPurpose::Effect | InvocationPurpose::Reconcile
        ),
        "metadata provisioning does not support compensation"
    );

    match role {
        MetadataRole::PlatformDetection => {
            let parameters: DetectionParameters = decode(&invocation.request.inputs)?;
            ensure!(
                parameters.request == intent,
                "detection request differs from the checked resource"
            );
            let platform = detect_platform()?;
            let evidence = detection_observation(Some(platform.platform_id.clone()), "detected")?;
            completed_result(
                &invocation,
                evidence,
                method_outputs([
                    (
                        "need-network",
                        ability_value(serde_json::to_value(platform.need_network)?)?,
                    ),
                    ("platform", ability_value(serde_json::to_value(platform)?)?),
                ])?,
            )
        }
        MetadataRole::Authorization => {
            let parameters: AuthorizationParameters = decode(&invocation.request.inputs)?;
            ensure!(
                parameters.request == intent,
                "authorization request differs from the checked resource"
            );
            let outputs = authorize(&parameters.configuration, &parameters.platform).await?;
            let evidence =
                authorization_observation(Some(outputs.authorized_input.source), "authorized")?;
            let authorized_input = serde_json::to_value(&outputs.authorized_input)?;
            let authorized_input_bytes =
                aos_contract::canonical::canonical_json(&authorized_input)?;
            publish_blob_output(AUTHORIZED_INPUT_SLOT, &authorized_input_bytes)?;
            completed_result(
                &invocation,
                evidence,
                method_outputs([
                    (
                        "authorized-provisioning-input",
                        ability_value(authorized_input)?,
                    ),
                    (
                        "authorized-input-blob",
                        ability_value(serde_json::to_value(TransactionBlobOutput {
                            kind: TRANSACTION_BLOB_OUTPUT_TYPE.into(),
                            slot: LocalKey::new(AUTHORIZED_INPUT_SLOT)?,
                        })?)?,
                    ),
                    (
                        "network-bootstrap",
                        ability_value(serde_json::to_value(outputs.network_bootstrap)?)?,
                    ),
                ])?,
            )
        }
        MetadataRole::PlanObservation => {
            let parameters: PlanParameters = decode(&invocation.request.inputs)?;
            ensure!(
                parameters.request == intent,
                "plan request differs from the checked resource"
            );
            let source = parameters.authorized_input.source;
            let nix_instantiate = required_tool("AOS_METADATA_NIX_INSTANTIATE")?;
            let plan = observe_plan(
                &parameters.request,
                &parameters.authorized_input,
                &parameters.marker,
                &nix_instantiate,
            )?;
            completed_result(
                &invocation,
                plan_observation(Some(source), "planned")?,
                method_outputs([(
                    "provisioning-plan",
                    ability_value(serde_json::to_value(plan)?)?,
                )])?,
            )
        }
        MetadataRole::ConfigurationEvaluation => {
            let parameters: EvaluationParameters = decode(&invocation.request.inputs)?;
            ensure!(
                parameters.request == intent,
                "configuration evaluation request differs from the checked resource"
            );
            let output = provisioning_evaluator::evaluate(parameters)?;
            publish_blob_output(MANIFEST_SLOT, &output.manifest)?;
            let manifest_sha256 = output.result.manifest_sha256.to_string();
            completed_result(
                &invocation,
                evaluation_observation(Some(manifest_sha256), "evaluated")?,
                method_outputs([(
                    "configuration-result",
                    ability_value(serde_json::to_value(output.result)?)?,
                )])?,
            )
        }
    }
}

fn detect_platform() -> Result<DetectedPlatform> {
    let scratch = Builder::new().prefix("aos-metadata-detection-").tempdir()?;
    let media_mountpoint = scratch.path().join("media");
    let environment = detect_environment(&media_mountpoint)?;
    finish_config_drive(&environment, detected_platform(&environment))
}

async fn authorize(
    configuration: &AuthorizationConfiguration,
    expected_platform: &DetectedPlatform,
) -> Result<AuthorizationOutputs> {
    validate_authorization_configuration(configuration)?;
    validate_detected_platform(expected_platform)?;
    let scratch = Builder::new()
        .prefix("aos-metadata-provisioning-")
        .tempdir()?;
    let stash_dir = scratch.path().join("stash");
    let media_mountpoint = scratch.path().join("media");
    let environment = detect_environment(&media_mountpoint)?;
    let actual_platform = match detected_platform(&environment) {
        Ok(platform) => platform,
        Err(error) => return finish_config_drive(&environment, Err(error)),
    };
    let outcome: Result<AuthorizationOutputs> = async {
        ensure!(
            actual_platform == *expected_platform,
            "metadata platform changed after the checked detection operation"
        );
        let stash = super::Stash::open(&stash_dir)?;
        stash.write_platform_env(&environment)?;
        run_fetch(&FetchOptions {
            stash_dir: stash_dir.clone(),
        })
        .await?;
        let (facts, network_bootstrap) = read_observed_instance_facts(&stash_dir)?;

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
                        platform_id: actual_platform.platform_id.clone(),
                        signer: result.signer,
                    },
                    facts: facts.clone(),
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
                    platform_id: actual_platform.platform_id.clone(),
                    signer: None,
                },
                facts,
                base_library: configuration.base_library.clone(),
            },
        };
        validate_authorized_provisioning_input(&input)?;
        Ok(AuthorizationOutputs {
            authorized_input: input,
            network_bootstrap,
        })
    }
    .await;
    finish_config_drive(&environment, outcome)
}

fn detect_environment(media_mountpoint: &Path) -> Result<super::stash::PlatformEnv> {
    detect(
        Path::new("/"),
        &BlkidProbe::with_tools(
            required_tool("AOS_METADATA_BLKID")?,
            required_tool("AOS_METADATA_MOUNT")?,
        ),
        media_mountpoint,
    )
}

fn detected_platform(environment: &super::stash::PlatformEnv) -> Result<DetectedPlatform> {
    let platform = DetectedPlatform {
        schema: "aos.metadata.provisioning-platform/v1".into(),
        platform_id: environment.platform_id.clone(),
        need_network: environment.need_network,
    };
    validate_detected_platform(&platform)?;
    Ok(platform)
}

fn validate_detected_platform(platform: &DetectedPlatform) -> Result<()> {
    ensure!(
        platform.schema == "aos.metadata.provisioning-platform/v1",
        "unsupported metadata platform result"
    );
    ensure!(
        platform_capability(&platform.platform_id).is_some(),
        "unsupported metadata platform"
    );
    ensure!(
        platform.need_network == needs_network(&platform.platform_id),
        "metadata platform network requirement is inconsistent"
    );
    Ok(())
}

fn finish_config_drive<T>(
    environment: &super::stash::PlatformEnv,
    outcome: Result<T>,
) -> Result<T> {
    let cleanup = if let Some(directory) = &environment.metadata_dir {
        let status = Command::new(required_tool("AOS_METADATA_UMOUNT")?)
            .arg(directory)
            .status()
            .context("unmounting metadata config drive")?;
        ensure!(status.success(), "metadata config-drive unmount failed");
        Ok(())
    } else {
        Ok(())
    };
    match (outcome, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(error.context(format!(
            "config-drive cleanup also failed: {cleanup_error:#}"
        ))),
    }
}

fn read_observed_instance_facts(
    stash_dir: &Path,
) -> Result<(
    aos_storage_provisioning::ObservedInstanceFacts,
    Option<AbilityValue>,
)> {
    let bytes =
        fs::read(stash_dir.join("facts.json")).context("reading normalized instance facts")?;
    let facts: super::fetcher::Facts =
        serde_json::from_slice(&bytes).context("decoding normalized instance facts")?;
    let facts = super::facts_render::canonicalize_host_facts(&facts)?;
    let network_bootstrap = facts
        .network
        .as_ref()
        .filter(|network| network.is_seedable())
        .map(network_bootstrap)
        .transpose()?;
    let observed = observed_instance_facts(serde_json::to_value(facts)?)?;

    Ok((observed, network_bootstrap))
}

fn network_bootstrap(network: &super::fetcher::StaticNetwork) -> Result<AbilityValue> {
    let selector = if let Some(mac) = network
        .mac
        .as_ref()
        .filter(|mac| super::fetcher::is_canonical_mac(mac))
    {
        BootstrapLinkSelector::Mac(mac.clone())
    } else if let Some(name) = network
        .interface_name
        .as_ref()
        .filter(|name| super::fetcher::is_exact_interface_name(name))
    {
        BootstrapLinkSelector::Name(name.clone())
    } else {
        bail!("seedable metadata network has no exact link selector")
    };

    BootstrapNetwork {
        selector,
        addresses: network.addresses.clone(),
        gateway: network.gateway.clone(),
        dns: network.dns.clone(),
    }
    .into_ability_value()
}

fn observe_plan(
    request: &ProvisioningIntent,
    input: &AuthorizedProvisioningInput,
    marker: &ProvisioningMarkerObservation,
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
    evaluate_canonical_provisioning_plan(&EvalProvisioningOptions {
        stash_dir,
        base_lib: PathBuf::from(&input.base_library.store_path),
        eval_root: scratch.path().join("eval"),
        measured_boot: request.measured_boot,
        marker: marker.clone(),
        nix_instantiate: nix_instantiate.to_path_buf(),
    })
}

fn publish_blob_output(slot: &str, contents: &[u8]) -> Result<()> {
    let output = std::env::var_os(TRANSACTION_BLOB_OUTPUT_DIRECTORY_ENV)
        .context("reading the private transaction blob output directory")?;
    let directory = PathBuf::from(output);
    ensure!(
        directory.is_absolute()
            && directory
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_))),
        "transaction blob output directory is not a normalized absolute path"
    );
    let metadata = fs::symlink_metadata(&directory)
        .context("inspecting the private transaction blob output directory")?;
    ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "transaction blob output directory is not a real directory"
    );
    ensure!(
        fs::canonicalize(&directory)? == directory,
        "transaction blob output directory is not canonical"
    );

    publish_blob_output_at(&directory, slot, contents)
}

fn publish_blob_output_at(directory: &Path, slot: &str, contents: &[u8]) -> Result<()> {
    let destination = directory.join(slot);
    match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
                "transaction blob output slot is not a regular file"
            );
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspecting the transaction blob output slot"),
    }

    let mut temporary = Builder::new()
        .prefix(".aos-transaction-blob-")
        .tempfile_in(&directory)
        .context("creating a private transaction blob output")?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temporary.write_all(contents)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(&destination)
        .map_err(|error| error.error)
        .context("publishing the transaction blob output")?;
    fs::File::open(&directory)?.sync_all()?;
    Ok(())
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

fn validate_method(role: MetadataRole, method: &str) -> Result<()> {
    ensure!(
        method == role.method(),
        "method differs from the selected metadata handler role"
    );
    Ok(())
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

fn detection_observation(platform_id: Option<String>, state: &'static str) -> Result<AbilityValue> {
    ability_value(serde_json::to_value(DetectionObservation {
        schema: DETECTION_OBSERVATION,
        platform_id,
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

fn evaluation_observation(
    manifest_sha256: Option<String>,
    state: &'static str,
) -> Result<AbilityValue> {
    ability_value(serde_json::to_value(EvaluationObservation {
        schema: EVALUATION_OBSERVATION,
        manifest_sha256,
        state,
    })?)
}

fn completed_result(
    invocation: &Invocation,
    evidence: AbilityValue,
    outputs: BTreeMap<LocalKey, AbilityValue>,
) -> Result<InvocationResult> {
    Ok(InvocationResult {
        schema: RESULT_SCHEMA.into(),
        disposition: InvocationDisposition::Completed,
        evidence,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

fn cancelled_result(invocation: &Invocation, role: MetadataRole) -> Result<InvocationResult> {
    let evidence = role.initial_observation()?;
    Ok(InvocationResult {
        schema: RESULT_SCHEMA.into(),
        disposition: InvocationDisposition::RejectedBeforeEffect,
        evidence,
        outputs: BTreeMap::new(),
        native_context_digest: invocation.request.native_context_digest,
    })
}

fn method_outputs<const N: usize>(
    entries: [(&str, AbilityValue); N],
) -> Result<BTreeMap<LocalKey, AbilityValue>> {
    entries
        .into_iter()
        .map(|(name, value)| Ok((LocalKey::new(name)?, value)))
        .collect()
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

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::os::unix::fs::{MetadataExt as _, symlink};

    use aos_ability_model::{InterfaceKey, InterfaceName};
    use aos_contract::Sha256Digest;

    use super::*;

    fn method_reference(interface: &str, method: &str) -> MethodReference {
        MethodReference {
            interface: InterfaceKey {
                name: InterfaceName::new(interface).expect("interface name"),
                abi: NonZeroU32::new(1).expect("non-zero ABI version"),
                descriptor: Sha256Digest::of_bytes(interface.as_bytes()),
            },
            method: LocalKey::new(method).expect("method name"),
        }
    }

    #[test]
    fn authenticated_methods_select_closed_metadata_roles() {
        let cases = [
            (
                "aos.metadata.storage-provisioning-platform-detection",
                MetadataRole::PlatformDetection,
                "detect",
            ),
            (
                "aos.metadata.storage-provisioning-input-authorization",
                MetadataRole::Authorization,
                "authorize",
            ),
            (
                "aos.metadata.storage-provisioning-plan",
                MetadataRole::PlanObservation,
                "observe",
            ),
            (
                "aos.configuration.storage-provisioning-evaluation",
                MetadataRole::ConfigurationEvaluation,
                "evaluate",
            ),
        ];

        for (interface, expected, method) in cases {
            let role = MetadataRole::from_method(&method_reference(interface, method))
                .expect("authenticated interface method selects a role");
            assert_eq!(role, expected);
            validate_method(role, method).expect("role method matches");
        }
        assert!(
            MetadataRole::from_method(&method_reference("aos.metadata.unknown", "detect")).is_err()
        );
    }

    #[test]
    fn canonical_network_facts_become_one_semantic_bootstrap_value() {
        let network = super::super::fetcher::StaticNetwork {
            mac: Some("02:00:00:00:00:01".to_string()),
            interface_name: Some("ens3".to_string()),
            addresses: vec!["192.0.2.10/24".to_string()],
            gateway: Some("192.0.2.1".to_string()),
            dns: vec!["192.0.2.53".to_string()],
        };

        let value = network_bootstrap(&network).expect("semantic bootstrap");

        assert_eq!(
            BootstrapNetwork::from_validated(&value).expect("bootstrap projection"),
            BootstrapNetwork {
                selector: BootstrapLinkSelector::Mac("02:00:00:00:00:01".to_string()),
                addresses: vec!["192.0.2.10/24".to_string()],
                gateway: Some("192.0.2.1".to_string()),
                dns: vec!["192.0.2.53".to_string()],
            }
        );
    }

    #[test]
    fn transaction_blob_publication_is_atomic_and_recoverable() {
        let directory = tempfile::tempdir().expect("private blob output directory");

        publish_blob_output_at(directory.path(), MANIFEST_SLOT, b"first")
            .expect("first blob publication");
        publish_blob_output_at(directory.path(), MANIFEST_SLOT, b"replacement")
            .expect("recovered blob publication");

        let path = directory.path().join(MANIFEST_SLOT);
        assert_eq!(fs::read(&path).expect("published blob"), b"replacement");
        assert_eq!(
            fs::metadata(path).expect("published blob metadata").mode() & 0o7777,
            0o600
        );
    }

    #[test]
    fn transaction_blob_publication_rejects_a_symbolic_link_slot() {
        let directory = tempfile::tempdir().expect("private blob output directory");
        let outside = tempfile::NamedTempFile::new().expect("outside file");
        symlink(outside.path(), directory.path().join(MANIFEST_SLOT)).expect("symbolic link");

        let error = publish_blob_output_at(directory.path(), MANIFEST_SLOT, b"manifest")
            .expect_err("symbolic link is rejected");

        assert!(error.to_string().contains("not a regular file"));
    }

    #[test]
    fn detected_platform_binds_network_requirement() {
        let cloud = DetectedPlatform {
            schema: "aos.metadata.provisioning-platform/v1".into(),
            platform_id: "aws".into(),
            need_network: true,
        };
        validate_detected_platform(&cloud).expect("cloud platform");

        let inconsistent = DetectedPlatform {
            need_network: false,
            ..cloud
        };
        let error =
            validate_detected_platform(&inconsistent).expect_err("network requirement differs");

        assert!(error.to_string().contains("network requirement"));
    }
}
