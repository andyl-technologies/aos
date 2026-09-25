//! Package-owned provider boundary for durable provisioning evaluation.

use std::collections::BTreeMap;
use std::io::{self, Read as _, Write as _};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, LocalKey, MethodReference, ResourceReference,
};
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, HANDLER_ABI_ARGUMENT, INVOCATION_SCHEMA, Invocation,
    InvocationDisposition, InvocationPurpose, InvocationResult, RESULT_SCHEMA, ResourceContext,
    SupportedPurposes, publish_transaction_blob_output, resource_set_digest,
    validate_admission_resource, validate_resource_context, validate_resource_contexts,
};
use aos_storage_provisioning::{ProvisioningIntent, validate_provisioning_intent};
use serde::{Deserialize, Serialize};

use super::provisioning_evaluator::{self, EvaluationParameters, MANIFEST_SLOT};
use crate::terminal_root::observe_package_root;

const INTERFACE: &str = "aos.configuration.storage-provisioning-evaluation";
const METHOD: &str = "evaluate";
const OBSERVATION_SCHEMA: &str = "aos.configuration.provisioning-evaluation-observation/v1";
const PROVIDER_CONTEXT_SCHEMA: &str = "aos.configuration.provisioning-evaluator-context/v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderContext {
    schema: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct EvaluationObservation {
    schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_sha256: Option<String>,
    state: &'static str,
}

/// Runs one retained-input configuration-evaluation call from process streams.
///
/// # Errors
///
/// Returns an error when the selected ABI, checked authority, retained input,
/// complete configuration evaluation, or provider result is invalid.
pub async fn run_from_process() -> Result<()> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    ensure!(
        arguments.len() == 3 && arguments[1] == HANDLER_ABI_ARGUMENT,
        "expected --aos-primitive-v1 and one purpose"
    );
    let purpose = arguments[2]
        .to_str()
        .context("provisioning evaluator purpose is not valid UTF-8")?;

    let mut input = Vec::new();
    io::stdin()
        .take(ABILITY_LIMITS_V1.max_document_bytes + 1)
        .read_to_end(&mut input)?;
    ensure!(
        input.len() as u64 <= ABILITY_LIMITS_V1.max_document_bytes,
        "protocol input exceeds the canonical document bound"
    );

    let value = match purpose {
        "observe-root" => serde_json::to_value(observe_package_root(
            &input,
            "storage-provisioning-configuration-evaluator",
            INTERFACE,
        )?)?,
        "admit" => {
            let request: AdmissionRequest =
                aos_contract::canonical::from_slice(&input, "provisioning evaluator admission")?;
            serde_json::to_value(admit(request)?)?
        }
        "effect" | "reconcile" | "cancel" => {
            let invocation: Invocation =
                aos_contract::canonical::from_slice(&input, "provisioning evaluator invocation")?;
            serde_json::to_value(invoke(invocation, purpose)?)?
        }
        purpose => bail!("unsupported provisioning evaluator purpose {purpose:?}"),
    };
    let output = aos_contract::canonical::canonical_json(&value)?;
    ensure!(
        output.len() <= aos_provider_protocol::MAX_HANDLER_RESULT_BYTES,
        "provisioning evaluator result exceeds the handler bound"
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
    validate_method(&request.method)?;
    let intent: ProvisioningIntent = decode(&request.resource_spec.value)?;
    validate_provisioning_intent(&intent)?;

    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.into(),
        disposition: AdmissionDisposition::Admitted,
        revision: AdmissionRevision::Absent,
        incarnation: Some(request.assignment.incarnation),
        observation: observation(None, "ready")?,
        native_context: ability_value(serde_json::to_value(ProviderContext {
            schema: PROVIDER_CONTEXT_SCHEMA.into(),
        })?)?,
        supported_purposes: SupportedPurposes::from_ordered(vec![
            InvocationPurpose::Effect,
            InvocationPurpose::Reconcile,
            InvocationPurpose::Cancel,
        ])
        .context("constructing provisioning evaluator purpose set")?,
    })
}

fn invoke(invocation: Invocation, purpose: &str) -> Result<InvocationResult> {
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
    validate_method(&invocation.method)?;
    validate_method(&invocation.request.method)?;
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
        provider_context.schema == PROVIDER_CONTEXT_SCHEMA,
        "provider context differs from the selected evaluator"
    );
    let intent: ProvisioningIntent = decode(&bound.resource_spec.value)?;
    validate_provisioning_intent(&intent)?;

    if invocation.control.cancelled || invocation.purpose == InvocationPurpose::Cancel {
        return Ok(InvocationResult {
            schema: RESULT_SCHEMA.into(),
            disposition: InvocationDisposition::RejectedBeforeEffect,
            evidence: observation(None, "ready")?,
            outputs: BTreeMap::new(),
            native_context_digest: invocation.request.native_context_digest,
        });
    }
    ensure!(
        matches!(
            invocation.purpose,
            InvocationPurpose::Effect | InvocationPurpose::Reconcile
        ),
        "provisioning evaluation does not support compensation"
    );

    let parameters: EvaluationParameters = decode(&invocation.request.inputs)?;
    ensure!(
        parameters.request == intent,
        "configuration evaluation request differs from the checked resource"
    );
    let output = provisioning_evaluator::evaluate(parameters)?;
    let slot = LocalKey::new(MANIFEST_SLOT)?;
    publish_transaction_blob_output(&slot, &output.manifest)?;
    let manifest_sha256 = output.result.manifest_sha256.to_string();
    let outputs = BTreeMap::from([
        (
            LocalKey::new("configuration-result")?,
            ability_value(serde_json::to_value(output.result)?)?,
        ),
        (
            LocalKey::new("provisioning-plan")?,
            ability_value(serde_json::to_value(output.provisioning_plan)?)?,
        ),
    ]);

    Ok(InvocationResult {
        schema: RESULT_SCHEMA.into(),
        disposition: InvocationDisposition::Completed,
        evidence: observation(Some(manifest_sha256), "evaluated")?,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

fn validate_method(method: &MethodReference) -> Result<()> {
    ensure!(
        method.interface.name.as_str() == INTERFACE && method.method.as_str() == METHOD,
        "interface method does not select the provisioning evaluator"
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

fn observation(manifest_sha256: Option<String>, state: &'static str) -> Result<AbilityValue> {
    ability_value(serde_json::to_value(EvaluationObservation {
        schema: OBSERVATION_SCHEMA,
        manifest_sha256,
        state,
    })?)
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

    #[test]
    fn evaluator_accepts_only_its_exact_interface_method() {
        let reference = MethodReference {
            interface: InterfaceKey {
                name: InterfaceName::new(INTERFACE).expect("interface name"),
                abi: NonZeroU32::MIN,
                descriptor: Sha256Digest::of_bytes(b"provisioning evaluator"),
            },
            method: LocalKey::new(METHOD).expect("method name"),
        };
        validate_method(&reference).expect("exact evaluator method");

        let mut other = reference;
        other.method = LocalKey::new("observe").expect("method name");
        assert!(validate_method(&other).is_err());
    }
}
