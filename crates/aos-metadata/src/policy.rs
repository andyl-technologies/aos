//! Package-owned metadata authorization and provisioning-plan handler.
//!
//! Exact host bytes and semantic early-network facts cross operations only
//! through protected typed outputs. Authorization consumes those values
//! directly; the plan observer materializes them only inside the private Nix
//! evaluator boundary.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use crate::AcquiredMetadata;
use crate::executable::ExecutableReference;
use crate::provisioning::evaluate_provisioning_plan;
use crate::trust::{CONFIG_SIGNATURE_NAMESPACE, authenticate_config_payload_files};
use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, ArtifactReference, LocalKey, MethodReference,
    ResourceReference,
};
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, HANDLER_ABI_ARGUMENT, INVOCATION_SCHEMA, Invocation,
    InvocationDisposition, InvocationPurpose, InvocationResult, RESULT_SCHEMA, ResourceContext,
    SupportedPurposes, TRANSACTION_BLOB_OUTPUT_TYPE, TransactionBlobOutput,
    publish_transaction_blob_output, resource_set_digest, validate_admission_resource,
    validate_resource_context, validate_resource_contexts,
};
use aos_storage_provisioning::{
    AuthorizedProvisioningInput, BaseLibraryIdentity, CanonicalProvisioningPlan,
    CanonicalProvisioningSource, ProvisioningAuthorization, ProvisioningIntent,
    ProvisioningMarkerObservation, ProvisioningTrustMode, observed_instance_facts,
    validate_authorized_provisioning_input, validate_provisioning_intent,
};
use serde::{Deserialize, Serialize};

const AUTHORIZATION_OBSERVATION: &str = "aos.metadata.provisioning-authorization-observation/v1";
const PLAN_OBSERVATION: &str = "aos.metadata.provisioning-plan-observation/v1";
const PROVIDER_CONTEXT: &str = "aos.metadata.provisioning-provider-context/v1";
const AUTHORIZED_INPUT_SLOT: &str = "authorized-provisioning-input";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum MetadataRole {
    Authorization,
    PlanObservation,
}

impl MetadataRole {
    fn from_method(method: &MethodReference) -> Result<Self> {
        match (method.interface.name.as_str(), method.method.as_str()) {
            ("aos.metadata.storage-provisioning-input-authorization", "authorize") => {
                Ok(Self::Authorization)
            }
            ("aos.metadata.storage-provisioning-plan", "observe") => Ok(Self::PlanObservation),
            _ => bail!("interface method does not select a checked metadata handler role"),
        }
    }

    const fn method(self) -> &'static str {
        match self {
            Self::Authorization => "authorize",
            Self::PlanObservation => "observe",
        }
    }

    fn initial_observation(self) -> Result<AbilityValue> {
        match self {
            Self::Authorization => authorization_observation(None, "ready"),
            Self::PlanObservation => plan_observation(None, "ready"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationParameters {
    request: ProvisioningIntent,
    configuration: AuthorizationConfiguration,
    acquired_metadata: AcquiredMetadata,
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
    nix_instantiate: ExecutableReference,
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
struct PlanObservation {
    schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<CanonicalProvisioningSource>,
    state: &'static str,
}

/// Runs an authorization or plan-normalization call from the process streams.
///
/// # Errors
///
/// Returns an error when the selected ABI, checked authority, metadata input,
/// restricted evaluation, or provider result is invalid.
pub async fn run_policy_provider_from_process() -> Result<()> {
    run_provider_from_process().await
}

async fn run_provider_from_process() -> Result<()> {
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
        MetadataRole::Authorization => {
            let parameters: AuthorizationParameters = decode(&invocation.request.inputs)?;
            ensure!(
                parameters.request == intent,
                "authorization request differs from the checked resource"
            );
            let input = authorize(&parameters.configuration, &parameters.acquired_metadata)?;
            let evidence = authorization_observation(Some(input.source), "authorized")?;
            let authorized_input = serde_json::to_value(&input)?;
            let authorized_input_bytes =
                aos_contract::canonical::canonical_json(&authorized_input)?;
            let output_slot = LocalKey::new(AUTHORIZED_INPUT_SLOT)?;
            publish_transaction_blob_output(&output_slot, &authorized_input_bytes)?;
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
            let nix_instantiate = parameters.nix_instantiate.resolve()?;
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
    }
}

fn authorize(
    configuration: &AuthorizationConfiguration,
    acquired: &AcquiredMetadata,
) -> Result<AuthorizedProvisioningInput> {
    validate_authorization_configuration(configuration)?;
    validate_acquired_metadata(acquired)?;
    authorize_validated_input(configuration, acquired)
}

fn authorize_validated_input(
    configuration: &AuthorizationConfiguration,
    acquired: &AcquiredMetadata,
) -> Result<AuthorizedProvisioningInput> {
    let facts = observed_instance_facts(serde_json::to_value(&acquired.facts)?)?;
    let input = match &acquired.host_module {
        Some(module) => {
            let signer = match configuration.trust_mode {
                ProvisioningTrustMode::Platform => None,
                ProvisioningTrustMode::Signed => {
                    let trusted_keys = trusted_key_files(&configuration.trusted_config_keys)?;
                    Some(
                        authenticate_config_payload_files(
                            module.as_bytes(),
                            acquired.host_module_signature.as_deref(),
                            &trusted_keys,
                            CONFIG_SIGNATURE_NAMESPACE,
                        )
                        .map_err(anyhow::Error::new)
                        .context("authorizing signed host module")?
                        .operator_key,
                    )
                }
            };

            AuthorizedProvisioningInput {
                schema: "aos.metadata.authorized-provisioning-input/v1".into(),
                source: CanonicalProvisioningSource::Operator,
                host_module: Some(module.clone()),
                host_module_sha256: Some(digest(module.as_bytes())),
                authorization: ProvisioningAuthorization {
                    trust_mode: configuration.trust_mode,
                    platform_id: acquired.platform_id.clone(),
                    signer,
                },
                facts,
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
                platform_id: acquired.platform_id.clone(),
                signer: None,
            },
            facts,
            base_library: configuration.base_library.clone(),
        },
    };
    validate_authorized_provisioning_input(&input)?;
    Ok(input)
}

fn validate_acquired_metadata(acquired: &AcquiredMetadata) -> Result<()> {
    ensure!(
        acquired.schema == "aos.metadata.acquired-provisioning-input/v1",
        "unsupported acquired metadata result"
    );
    crate::detect::PlatformId::parse(&acquired.platform_id)?;
    ensure!(
        acquired.host_module.is_some() || acquired.host_module_signature.is_none(),
        "metadata signature has no corresponding host module"
    );
    ensure!(
        crate::canonicalize_host_facts(&acquired.facts)? == acquired.facts,
        "acquired metadata facts are not canonical"
    );
    Ok(())
}

fn observe_plan(
    request: &ProvisioningIntent,
    input: &AuthorizedProvisioningInput,
    marker: &ProvisioningMarkerObservation,
    nix_instantiate: &Path,
) -> Result<CanonicalProvisioningPlan> {
    validate_authorized_provisioning_input(input)?;
    verify_base_library(&input.base_library)?;
    evaluate_provisioning_plan(request, input, marker, nix_instantiate)
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
    let mut names = std::collections::BTreeSet::new();
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
        if paths.iter().any(|existing| existing == &path) {
            continue;
        }
        let name = path
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
        paths.push(path);
    }
    Ok(paths)
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
                "aos.metadata.storage-provisioning-input-authorization",
                MetadataRole::Authorization,
                "authorize",
            ),
            (
                "aos.metadata.storage-provisioning-plan",
                MetadataRole::PlanObservation,
                "observe",
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
    fn platform_authorization_preserves_typed_input_without_file_round_trip() {
        let host_module = "{ aos.provisioning.storage.partitions = {}; }";
        let configuration = AuthorizationConfiguration {
            schema: "aos.metadata.provisioning-authorization-configuration/v1".into(),
            trust_mode: ProvisioningTrustMode::Platform,
            trusted_config_keys: Vec::new(),
            base_library: BaseLibraryIdentity {
                store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-base-lib".into(),
                abi_hash: format!("sha256:{}", "00".repeat(32)),
            },
        };
        let acquired = AcquiredMetadata {
            schema: "aos.metadata.acquired-provisioning-input/v1".into(),
            platform_id: "qemu".into(),
            host_module: Some(host_module.into()),
            host_module_signature: None,
            facts: crate::Facts {
                hostname: Some("provisioning-test".into()),
                ..Default::default()
            },
        };

        let authorized =
            authorize_validated_input(&configuration, &acquired).expect("typed authorization");

        assert_eq!(authorized.source, CanonicalProvisioningSource::Operator);
        assert_eq!(authorized.host_module.as_deref(), Some(host_module));
        assert_eq!(
            authorized.host_module_sha256,
            Some(digest(host_module.as_bytes()))
        );
        assert_eq!(authorized.authorization.signer, None);
        assert_eq!(
            authorized.facts.value["hostname"],
            serde_json::Value::String("provisioning-test".into())
        );
    }
}
