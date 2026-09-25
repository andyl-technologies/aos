//! Package-owned platform detection and metadata acquisition ability handler.
//!
//! The provider receives exact native executables through checked method
//! parameters. Mounted media and fetched bytes remain private to one invocation;
//! only typed operation results cross into the generic authorization provider.

use std::collections::BTreeMap;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, LocalKey, MethodReference, ResourceReference,
};
use aos_net::{BootstrapLinkSelector, BootstrapNetwork};
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, HANDLER_ABI_ARGUMENT, INVOCATION_SCHEMA, Invocation,
    InvocationDisposition, InvocationPurpose, InvocationResult, RESULT_SCHEMA, ResourceContext,
    SupportedPurposes, resource_set_digest, validate_admission_resource, validate_resource_context,
    validate_resource_contexts,
};
use aos_storage_provisioning::{ProvisioningIntent, validate_provisioning_intent};
use serde::{Deserialize, Serialize};
use tempfile::Builder;

use crate::detect::{AcquisitionContext, PlatformId, detect};
use crate::executable::ExecutableReference;
use crate::mount::BlkidProbe;
use crate::root_observation::{MetadataHandler, observe_root};
use crate::{AcquiredMetadata, DetectedPlatform, fetch_metadata};

const ACQUIRED_METADATA_SCHEMA: &str = "aos.metadata.acquired-provisioning-input/v1";
const ACQUISITION_OBSERVATION: &str = "aos.metadata.provisioning-acquisition-observation/v1";
const DETECTED_PLATFORM_SCHEMA: &str = "aos.metadata.provisioning-platform/v1";
const DETECTION_OBSERVATION: &str = "aos.metadata.provisioning-platform-observation/v1";
const PROVIDER_CONTEXT: &str = "aos.metadata.acquisition-provider-context/v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum MetadataRole {
    Acquisition,
    PlatformDetection,
}

impl MetadataRole {
    fn from_method(method: &MethodReference) -> Result<Self> {
        match (method.interface.name.as_str(), method.method.as_str()) {
            ("aos.metadata.storage-provisioning-acquisition", "acquire") => Ok(Self::Acquisition),
            ("aos.metadata.storage-provisioning-platform-detection", "detect") => {
                Ok(Self::PlatformDetection)
            }
            _ => bail!("interface method does not select a checked acquisition role"),
        }
    }

    const fn method(self) -> &'static str {
        match self {
            Self::Acquisition => "acquire",
            Self::PlatformDetection => "detect",
        }
    }

    fn initial_observation(self) -> Result<AbilityValue> {
        match self {
            Self::Acquisition => acquisition_observation(None, "ready"),
            Self::PlatformDetection => detection_observation(None, "ready"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetectionParameters {
    request: ProvisioningIntent,
    blkid: ExecutableReference,
    mount: ExecutableReference,
    umount: ExecutableReference,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcquisitionParameters {
    request: ProvisioningIntent,
    platform: DetectedPlatform,
    blkid: ExecutableReference,
    mount: ExecutableReference,
    umount: ExecutableReference,
}

#[derive(Debug)]
struct NativeTools {
    blkid: PathBuf,
    mount: PathBuf,
    umount: PathBuf,
}

impl NativeTools {
    fn resolve(
        blkid: &ExecutableReference,
        mount: &ExecutableReference,
        umount: &ExecutableReference,
    ) -> Result<Self> {
        Ok(Self {
            blkid: blkid.resolve()?,
            mount: mount.resolve()?,
            umount: umount.resolve()?,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderContext {
    schema: String,
    role: MetadataRole,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct AcquisitionObservation {
    schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    platform_id: Option<String>,
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

/// Runs one selected metadata provider call from the process streams.
///
/// # Errors
///
/// Returns an error when the ABI, checked authority, executable references,
/// platform result, acquisition, or result envelope is invalid.
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
        "observe-root" => {
            let request: aos_provider_protocol::RootObservationRequest =
                aos_contract::canonical::from_slice(&input, "metadata root observation")?;
            serde_json::to_value(observe_root(MetadataHandler::Acquisition, request)?)?
        }
        "admit" => {
            let request: AdmissionRequest =
                aos_contract::canonical::from_slice(&input, "metadata acquisition admission")?;
            let role = MetadataRole::from_method(&request.method)?;
            serde_json::to_value(admit(role, request)?)?
        }
        "effect" | "reconcile" | "cancel" => {
            let invocation: Invocation =
                aos_contract::canonical::from_slice(&input, "metadata acquisition invocation")?;
            let role = MetadataRole::from_method(&invocation.method)?;
            serde_json::to_value(invoke(role, invocation, purpose).await?)?
        }
        purpose => bail!("unsupported metadata acquisition purpose {purpose:?}"),
    };
    let output = aos_contract::canonical::canonical_json(&value)?;
    ensure!(
        output.len() <= aos_provider_protocol::MAX_HANDLER_RESULT_BYTES,
        "metadata acquisition result exceeds the handler bound"
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

    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.into(),
        disposition: AdmissionDisposition::Admitted,
        revision: AdmissionRevision::Absent,
        incarnation: Some(request.assignment.incarnation),
        observation: role.initial_observation()?,
        native_context: ability_value(serde_json::to_value(ProviderContext {
            schema: PROVIDER_CONTEXT.into(),
            role,
        })?)?,
        supported_purposes: SupportedPurposes::from_ordered(vec![
            InvocationPurpose::Effect,
            InvocationPurpose::Reconcile,
            InvocationPurpose::Cancel,
        ])
        .context("constructing metadata acquisition purpose set")?,
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
        "metadata acquisition does not support compensation"
    );

    match role {
        MetadataRole::PlatformDetection => {
            let parameters: DetectionParameters = decode(&invocation.request.inputs)?;
            ensure!(
                parameters.request == intent,
                "detection request differs from the checked resource"
            );
            let tools =
                NativeTools::resolve(&parameters.blkid, &parameters.mount, &parameters.umount)?;
            let platform = detect_platform(&tools)?;
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
        MetadataRole::Acquisition => {
            let parameters: AcquisitionParameters = decode(&invocation.request.inputs)?;
            ensure!(
                parameters.request == intent,
                "acquisition request differs from the checked resource"
            );
            let tools =
                NativeTools::resolve(&parameters.blkid, &parameters.mount, &parameters.umount)?;
            let (acquired, network_bootstrap) = acquire(&parameters.platform, &tools).await?;
            let evidence = acquisition_observation(Some(acquired.platform_id.clone()), "acquired")?;
            completed_result(
                &invocation,
                evidence,
                method_outputs([
                    (
                        "acquired-metadata",
                        ability_value(serde_json::to_value(acquired)?)?,
                    ),
                    (
                        "network-bootstrap",
                        ability_value(serde_json::to_value(network_bootstrap)?)?,
                    ),
                ])?,
            )
        }
    }
}

fn detect_platform(tools: &NativeTools) -> Result<DetectedPlatform> {
    let scratch = Builder::new().prefix("aos-metadata-detection-").tempdir()?;
    let context = detect_environment(scratch.path().join("media"), tools)?;
    let platform = detected_platform(&context);
    finish_config_drive(&context, tools, platform)
}

async fn acquire(
    expected_platform: &DetectedPlatform,
    tools: &NativeTools,
) -> Result<(AcquiredMetadata, Option<AbilityValue>)> {
    validate_detected_platform(expected_platform)?;
    let scratch = Builder::new()
        .prefix("aos-metadata-acquisition-")
        .tempdir()?;
    let context = detect_environment(scratch.path().join("media"), tools)?;
    let actual_platform = detected_platform(&context);
    let actual_platform = match actual_platform {
        Ok(platform) => platform,
        Err(error) => return finish_config_drive(&context, tools, Err(error)),
    };

    let outcome: Result<(AcquiredMetadata, Option<AbilityValue>)> = async {
        ensure!(
            actual_platform == *expected_platform,
            "metadata platform changed after the checked detection operation"
        );
        let fetched = fetch_metadata(&context).await?;
        let facts = fetched.facts;
        let network_bootstrap = facts
            .network
            .as_ref()
            .filter(|network| network.is_seedable())
            .map(network_bootstrap)
            .transpose()?;
        Ok((
            AcquiredMetadata {
                schema: ACQUIRED_METADATA_SCHEMA.into(),
                platform_id: actual_platform.platform_id,
                host_module: fetched.host_module,
                host_module_signature: fetched.host_module_signature,
                facts,
            },
            network_bootstrap,
        ))
    }
    .await;
    finish_config_drive(&context, tools, outcome)
}

fn detect_environment(mountpoint: PathBuf, tools: &NativeTools) -> Result<AcquisitionContext> {
    detect(
        Path::new("/"),
        &BlkidProbe::with_tools(&tools.blkid, &tools.mount),
        &mountpoint,
    )
}

fn detected_platform(context: &AcquisitionContext) -> Result<DetectedPlatform> {
    let platform = DetectedPlatform {
        schema: DETECTED_PLATFORM_SCHEMA.into(),
        platform_id: context.platform.as_str().into(),
        need_network: context.needs_network(),
    };
    validate_detected_platform(&platform)?;
    Ok(platform)
}

/// Validates a platform result against the package-owned platform model.
///
/// # Errors
///
/// Returns an error when the schema or identifier is unknown or the network
/// requirement differs from the selected platform capability.
pub fn validate_detected_platform(platform: &DetectedPlatform) -> Result<()> {
    ensure!(
        platform.schema == DETECTED_PLATFORM_SCHEMA,
        "unsupported metadata platform result"
    );
    let selected = PlatformId::parse(&platform.platform_id)?;
    ensure!(
        platform.need_network
            == matches!(
                selected.capability(),
                crate::detect::PlatformCapability::NetworkMetadata
            ),
        "metadata platform network requirement is inconsistent"
    );
    Ok(())
}

fn finish_config_drive<T>(
    context: &AcquisitionContext,
    tools: &NativeTools,
    outcome: Result<T>,
) -> Result<T> {
    let cleanup = if let Some(directory) = &context.metadata_dir {
        let status = Command::new(&tools.umount)
            .arg(directory)
            .env_clear()
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

fn network_bootstrap(network: &crate::fetcher::StaticNetwork) -> Result<AbilityValue> {
    let selector = if let Some(mac) = network
        .mac
        .as_ref()
        .filter(|mac| crate::fetcher::is_canonical_mac(mac))
    {
        BootstrapLinkSelector::Mac(mac.clone())
    } else if let Some(name) = network
        .interface_name
        .as_ref()
        .filter(|name| crate::fetcher::is_exact_interface_name(name))
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

fn validate_method(role: MetadataRole, method: &str) -> Result<()> {
    ensure!(
        method == role.method(),
        "method differs from the selected metadata acquisition role"
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

fn acquisition_observation(
    platform_id: Option<String>,
    state: &'static str,
) -> Result<AbilityValue> {
    ability_value(serde_json::to_value(AcquisitionObservation {
        schema: ACQUISITION_OBSERVATION,
        platform_id,
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
    Ok(InvocationResult {
        schema: RESULT_SCHEMA.into(),
        disposition: InvocationDisposition::RejectedBeforeEffect,
        evidence: role.initial_observation()?,
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
    fn authenticated_methods_select_closed_acquisition_roles() {
        let cases = [
            (
                "aos.metadata.storage-provisioning-platform-detection",
                MetadataRole::PlatformDetection,
                "detect",
            ),
            (
                "aos.metadata.storage-provisioning-acquisition",
                MetadataRole::Acquisition,
                "acquire",
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
    fn detected_platform_binds_network_requirement() {
        let cloud = DetectedPlatform {
            schema: DETECTED_PLATFORM_SCHEMA.into(),
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
