//! Package-owned systemd ability handler.
//!
//! The binary implements the bounded AOS provider protocol for exact packaged
//! unit activation. It validates and materializes only the realization carried
//! by the checked target resource, then drives the pinned systemd manager over
//! D-Bus.

mod materialize;
mod model;
mod render;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use aos_ability_model::{AbilityValue, IncarnationId, LocalKey};
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, BoundNativeContext, HANDLER_ABI_ARGUMENT,
    INVOCATION_SCHEMA, Invocation, InvocationDisposition, InvocationPurpose, InvocationResult,
    REQUEST_SCHEMA, RESOURCE_CONTEXT_SCHEMA, RESULT_SCHEMA, ResourceContext, SupportedPurposes,
    native_context_digest, resource_set_digest,
};
use aos_systemd::{PinnedSystemdManager, UnitActiveState};
use serde::Serialize;

use crate::materialize::{UnitPaths, matches, materialize, paths_for};
use crate::model::{
    Activation, INTERFACE_NAME, OBSERVATION_SCHEMA, PackagedUnitObservation,
    PackagedUnitRealization, PackagedUnitRequest, ProviderContext, UnitState, empty_outputs,
};
use crate::render::{RenderedUnit, render};

const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
const ETC_ROOT: &str = "/etc";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("aos-systemd-provider: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 3 || arguments[1] != HANDLER_ABI_ARGUMENT {
        bail!("expected --aos-primitive-v1 and one invocation purpose");
    }
    let bytes = read_input()?;
    match arguments[2].as_str() {
        "admit" => {
            let request: AdmissionRequest = decode_canonical(&bytes)?;
            let timeout = deadline(request.control.attempt_remaining_millis);
            let result = tokio::time::timeout(timeout, admit(request))
                .await
                .context("admission deadline expired")??;
            write_output(&result)
        }
        purpose => {
            let request: Invocation = decode_canonical(&bytes)?;
            if serde_json::to_value(request.purpose)? != serde_json::Value::String(purpose.into()) {
                bail!("argv purpose does not match the invocation envelope");
            }
            let timeout = deadline(
                request
                    .control
                    .attempt_remaining_millis
                    .min(request.control.recovery_remaining_millis),
            );
            let result = tokio::time::timeout(timeout, invoke(request))
                .await
                .context("invocation deadline expired")??;
            write_output(&result)
        }
    }
}

async fn admit(request: AdmissionRequest) -> Result<AdmissionResult> {
    if request.schema != ADMISSION_REQUEST_SCHEMA {
        bail!("unsupported admission request schema");
    }
    require_interface(&request.method)?;
    if request.target.resource != request.resource_spec.resource {
        bail!("admission target does not match its resource specification");
    }
    validate_contexts(&request.resources)?;

    let expected: PackagedUnitRequest = decode_value(&request.resource_spec.value)?;
    let realization: PackagedUnitRealization = decode_value(&request.resource_spec.realization)?;
    require_matching_request(&expected, &realization)?;
    let rendered = render(&realization)?;
    let paths = paths_for(Path::new(ETC_ROOT), &realization.systemd_unit.unit_name);

    let manager = PinnedSystemdManager::connect().await?;
    let inspection = inspect(
        &manager,
        &expected,
        &realization,
        &request.resource_spec.resource,
        request.resource_spec.revision,
        &rendered,
        &paths,
    )
    .await?;
    let incarnation = IncarnationId::new(manager.incarnation().token())?;
    let provider_context = provider_context(&manager, inspection.unit_identity.clone())?;
    let supported_purposes = SupportedPurposes::from_ordered(vec![
        InvocationPurpose::Effect,
        InvocationPurpose::Reconcile,
    ])
    .ok_or_else(|| anyhow::anyhow!("provider purpose set is not canonical"))?;

    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.to_string(),
        disposition: AdmissionDisposition::Admitted,
        revision: if inspection.revision_matches {
            AdmissionRevision::Present {
                revision: request.resource_spec.revision,
            }
        } else {
            AdmissionRevision::Absent
        },
        incarnation: Some(incarnation),
        observation: value(&inspection.observation)?,
        native_context: provider_context,
        supported_purposes,
    })
}

async fn invoke(invocation: Invocation) -> Result<InvocationResult> {
    if invocation.schema != INVOCATION_SCHEMA || invocation.request.schema != REQUEST_SCHEMA {
        bail!("unsupported invocation schema");
    }
    if !invocation.method_is_bound() {
        bail!("invocation method is not bound to its durable recovery contract");
    }
    require_interface(&invocation.method)?;
    if resource_set_digest(&invocation.request.resources)?
        != invocation.request.native_context_digest
    {
        bail!("invocation resource-set digest does not match");
    }
    validate_contexts(&invocation.request.resources)?;

    let target = target_context(&invocation)?;
    let bound: BoundNativeContext = decode_value(&target.native_context)?;
    if bound.schema != RESOURCE_CONTEXT_SCHEMA
        || bound.resource_spec.resource != invocation.request.target.resource
    {
        bail!("target context is bound to another resource");
    }
    let expected: PackagedUnitRequest = decode_value(&bound.resource_spec.value)?;
    let method_inputs: PackagedUnitRequest = decode_value(&invocation.request.inputs)?;
    if method_inputs != expected {
        bail!("invocation inputs differ from the checked target value");
    }
    let realization: PackagedUnitRealization = decode_value(&bound.resource_spec.realization)?;
    require_matching_request(&expected, &realization)?;
    let provider: ProviderContext = decode_value(&bound.provider_context)?;
    if provider.schema != model::PROVIDER_CONTEXT_SCHEMA {
        bail!("unsupported provider context schema");
    }

    let manager = PinnedSystemdManager::connect().await?;
    if manager.incarnation().bus_id() != provider.manager_bus_id
        || manager.incarnation().owner() != provider.manager_owner
    {
        bail!("systemd manager changed after admission");
    }
    let rendered = render(&realization)?;
    let paths = paths_for(Path::new(ETC_ROOT), &realization.systemd_unit.unit_name);

    let primary_method = invocation.request.method.method.as_str();
    let selected_method = invocation.method.method.as_str();
    let inspection = match invocation.purpose {
        InvocationPurpose::Effect if selected_method == "apply" => {
            materialize(
                Path::new(ETC_ROOT),
                &realization.systemd_unit.unit_name,
                bound.resource_spec.revision,
                &bound.resource_spec.resource,
                &rendered,
            )?;
            manager.daemon_reload().await?;
            let identity = manager
                .load_unit(&realization.systemd_unit.unit_name)
                .await?;
            if let Some(expected_identity) = &provider.unit_identity
                && expected_identity != &identity
            {
                bail!("systemd unit identity changed after admission");
            }
            if realization.activation == Activation::Enabled {
                let outcome = manager
                    .start_unit_exact_receipt(
                        &realization.systemd_unit.unit_name,
                        &identity,
                        &format!("file:{}", realization.revision_receipt),
                    )
                    .await?;
                if !outcome.result.is_done() {
                    bail!("systemd start job completed as {}", outcome.result.label());
                }
            }
            inspect(
                &manager,
                &expected,
                &realization,
                &bound.resource_spec.resource,
                bound.resource_spec.revision,
                &rendered,
                &paths,
            )
            .await?
        }
        InvocationPurpose::Effect if selected_method == "observe" => {
            inspect(
                &manager,
                &expected,
                &realization,
                &bound.resource_spec.resource,
                bound.resource_spec.revision,
                &rendered,
                &paths,
            )
            .await?
        }
        InvocationPurpose::Reconcile if selected_method == "observe" => {
            inspect(
                &manager,
                &expected,
                &realization,
                &bound.resource_spec.resource,
                bound.resource_spec.revision,
                &rendered,
                &paths,
            )
            .await?
        }
        InvocationPurpose::Cancel
        | InvocationPurpose::Compensate
        | InvocationPurpose::ReconcileCompensation => {
            bail!("systemd packaged-unit provider does not advertise this purpose");
        }
        _ => bail!("unsupported systemd packaged-unit method"),
    };

    let completed = match invocation.purpose {
        InvocationPurpose::Effect if selected_method == "apply" => inspection.complete,
        InvocationPurpose::Effect if selected_method == "observe" => true,
        InvocationPurpose::Reconcile if selected_method == "observe" => {
            primary_method == "observe" || inspection.complete
        }
        _ => false,
    };
    let disposition = if completed {
        InvocationDisposition::Completed
    } else {
        InvocationDisposition::SafeToRetry
    };
    let outputs = if completed {
        outputs_for(primary_method, &inspection.observation, &invocation)?
    } else {
        empty_outputs()
    };
    Ok(InvocationResult {
        schema: RESULT_SCHEMA.to_string(),
        disposition,
        evidence: value(&inspection.observation)?,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

struct Inspection {
    observation: PackagedUnitObservation,
    unit_identity: Option<String>,
    revision_matches: bool,
    complete: bool,
}

async fn inspect(
    manager: &PinnedSystemdManager,
    expected: &PackagedUnitRequest,
    realization: &PackagedUnitRealization,
    resource: &aos_ability_model::ResourceId,
    revision: aos_ability_model::RevisionId,
    rendered: &RenderedUnit,
    paths: &UnitPaths,
) -> Result<Inspection> {
    let files_match = matches(
        paths,
        rendered,
        resource,
        &realization.systemd_unit.unit_name,
        revision,
    )?;
    let unit_identity = match manager
        .unit_identity(&realization.systemd_unit.unit_name)
        .await
    {
        Ok(identity) => Some(identity),
        Err(error) if error.is_no_such_unit() => None,
        Err(error) => return Err(error.into()),
    };
    let (state, revision_matches) = if let Some(identity) = &unit_identity {
        let state = manager
            .active_state_exact(&realization.systemd_unit.unit_name, identity)
            .await?;
        let revision_matches = match manager
            .unit_identity_at_receipt(
                &realization.systemd_unit.unit_name,
                &format!("file:{}", realization.revision_receipt),
            )
            .await
        {
            Ok(revision_identity) if revision_identity == *identity => true,
            Ok(_) => bail!("systemd unit identity changed while observing its revision"),
            Err(error) if error.is_authority_mismatch() || error.is_no_such_unit() => false,
            Err(error) => return Err(error.into()),
        };
        (unit_state(state), revision_matches)
    } else {
        (UnitState::Absent, false)
    };
    let activation_matches =
        realization.activation == Activation::Reference || state == UnitState::Active;
    let complete = files_match && revision_matches && activation_matches;
    let mut discrepancies = Vec::new();
    if !files_match {
        discrepancies.push("drop_in".to_string());
    }
    if !revision_matches {
        discrepancies.push("revision".to_string());
    }
    if !activation_matches {
        discrepancies.push("state".to_string());
    }
    let observed = complete.then(|| normalized_request(expected, realization));
    Ok(Inspection {
        observation: PackagedUnitObservation {
            schema: OBSERVATION_SCHEMA.to_string(),
            expected: expected.clone(),
            observed,
            unit_name: realization.systemd_unit.unit_name.clone(),
            state,
            discrepancies,
        },
        unit_identity,
        revision_matches,
        complete,
    })
}

fn provider_context(
    manager: &PinnedSystemdManager,
    unit_identity: Option<String>,
) -> Result<AbilityValue> {
    value(&ProviderContext {
        schema: model::PROVIDER_CONTEXT_SCHEMA.to_string(),
        manager_bus_id: manager.incarnation().bus_id().to_string(),
        manager_owner: manager.incarnation().owner().to_string(),
        unit_identity,
    })
}

fn outputs_for(
    method: &str,
    observation: &PackagedUnitObservation,
    invocation: &Invocation,
) -> Result<BTreeMap<LocalKey, AbilityValue>> {
    let mut outputs = BTreeMap::new();
    outputs.insert(LocalKey::new("observation")?, value(observation)?);
    if method == "apply" {
        outputs.insert(
            LocalKey::new("retained-resource")?,
            value(&invocation.request.target)?,
        );
    }
    Ok(outputs)
}

fn target_context(invocation: &Invocation) -> Result<&ResourceContext> {
    let matches = invocation
        .request
        .resources
        .iter()
        .filter(|context| context.reference.resource == invocation.request.target.resource)
        .collect::<Vec<_>>();
    if matches.len() != 1 || matches[0].reference != invocation.request.target {
        bail!("invocation target does not have one exact checked context");
    }
    Ok(matches[0])
}

fn validate_contexts(contexts: &[ResourceContext]) -> Result<()> {
    for context in contexts {
        if native_context_digest(&context.native_context)? != context.native_context_digest {
            bail!("resource native-context digest does not match");
        }
    }
    Ok(())
}

fn require_interface(method: &aos_ability_model::MethodReference) -> Result<()> {
    if method.interface.name.as_str() != INTERFACE_NAME {
        bail!("handler invocation selects another interface");
    }
    if !matches!(method.method.as_str(), "apply" | "observe") {
        bail!("handler invocation selects an unsupported method");
    }
    Ok(())
}

fn require_matching_request(
    expected: &PackagedUnitRequest,
    realization: &PackagedUnitRealization,
) -> Result<()> {
    if expected.source.artifact != realization.source.artifact
        || expected.source.unit_file != realization.source.unit_file
        || expected
            .source
            .unit_name
            .as_ref()
            .is_some_and(|name| name != &realization.systemd_unit.unit_name)
        || expected.activation != realization.activation
    {
        bail!("systemd realization does not exactly normalize its checked request");
    }
    Ok(())
}

fn normalized_request(
    expected: &PackagedUnitRequest,
    realization: &PackagedUnitRealization,
) -> PackagedUnitRequest {
    let mut normalized = expected.clone();
    normalized.source.unit_name = Some(realization.systemd_unit.unit_name.clone());
    normalized
}

fn unit_state(state: UnitActiveState) -> UnitState {
    match state {
        UnitActiveState::Active | UnitActiveState::Reloading => UnitState::Active,
        UnitActiveState::Inactive => UnitState::Inactive,
        UnitActiveState::Failed => UnitState::Failed,
        UnitActiveState::Activating
        | UnitActiveState::Deactivating
        | UnitActiveState::Maintenance
        | UnitActiveState::Refreshing
        | UnitActiveState::Unknown(_) => UnitState::Unknown,
    }
}

fn value<T: Serialize>(input: &T) -> Result<AbilityValue> {
    AbilityValue::new(serde_json::to_value(input)?).map_err(Into::into)
}

fn decode_value<T: serde::de::DeserializeOwned>(input: &AbilityValue) -> Result<T> {
    serde_json::from_value(input.as_json().clone()).context("decoding checked provider value")
}

fn decode_canonical<T>(bytes: &[u8]) -> Result<T>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(bytes).context("decoding canonical handler input")?;
    let canonical =
        aos_contract::canonical::to_vec(&value).context("canonicalizing handler input")?;
    if canonical != bytes {
        bail!("handler input is not canonical JSON");
    }
    Ok(value)
}

fn read_input() -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("reading handler input")?;
    if bytes.len() > MAX_INPUT_BYTES {
        bail!("handler input exceeds its byte bound");
    }
    Ok(bytes)
}

fn write_output<T: Serialize>(output: &T) -> Result<()> {
    let bytes = aos_contract::canonical::to_vec(output).context("encoding handler output")?;
    if bytes.len() > aos_provider_protocol::MAX_HANDLER_RESULT_BYTES {
        bail!("handler result exceeds its byte bound");
    }
    std::io::stdout()
        .write_all(&bytes)
        .context("writing handler output")
}

fn deadline(milliseconds: u64) -> Duration {
    Duration::from_millis(milliseconds.max(1))
}
