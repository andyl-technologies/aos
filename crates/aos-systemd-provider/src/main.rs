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
use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, AccessMode, IncarnationId, LocalKey, MethodSemantics,
    RevisionId,
};
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, BoundNativeContext, HANDLER_ABI_ARGUMENT,
    INVOCATION_SCHEMA, Invocation, InvocationDisposition, InvocationPurpose, InvocationResult,
    REQUEST_SCHEMA, RESOURCE_CONTEXT_SCHEMA, RESULT_SCHEMA, ResourceContext, SupportedPurposes,
    native_context_digest, resource_set_digest,
};
use aos_systemd::{PinnedSystemdManager, UnitActiveState};
use serde::Serialize;

use crate::materialize::{
    UnitPaths, is_absent, matches, materialize, paths_for, remove, validate_removal,
};
use crate::model::{
    Activation, INTERFACE_NAME, OBSERVATION_SCHEMA, PackagedUnitObservation,
    PackagedUnitRealization, PackagedUnitRequest, ProviderContext, UnitState, empty_outputs,
};
use crate::render::{RenderedUnit, render};

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
    require_method(&request.method, &request.semantics)?;
    if request.target.resource != request.resource_spec.resource {
        bail!("admission target does not match its resource specification");
    }
    validate_contexts(&request.resources)?;

    let expected: PackagedUnitRequest = decode_value(&request.resource_spec.value)?;
    require_prerequisite_contexts(&expected.prerequisites, &request.resources)?;
    let realization: PackagedUnitRealization = decode_value(&request.resource_spec.realization)?;
    require_matching_request(&expected, &realization)?;
    let rendered = render(&realization)?;
    let paths = paths_for(
        Path::new(ETC_ROOT),
        &realization.systemd_unit.unit_name,
        request.resource_spec.revision,
    );

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
    let provider_context = provider_context(
        &manager,
        inspection.unit_identity.clone(),
        inspection.materialization_matches,
    )?;
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
    require_method(&invocation.method, &invocation.semantics)?;
    require_method(&invocation.request.method, &invocation.request.semantics)?;
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
    require_target_revision(bound.resource_spec.revision, target.revision)?;
    let expected: PackagedUnitRequest = decode_value(&bound.resource_spec.value)?;
    require_prerequisite_contexts(&expected.prerequisites, &invocation.request.resources)?;
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
    let paths = paths_for(
        Path::new(ETC_ROOT),
        &realization.systemd_unit.unit_name,
        bound.resource_spec.revision,
    );

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
                    .start_unit_exact_current(&realization.systemd_unit.unit_name, &identity)
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
        InvocationPurpose::Effect if selected_method == "remove" => {
            validate_removal(
                &paths,
                &rendered,
                &bound.resource_spec.resource,
                &realization.systemd_unit.unit_name,
                bound.resource_spec.revision,
            )?;
            if provider.unit_owned
                && let Some(identity) = &provider.unit_identity
            {
                let outcome = manager
                    .stop_unit_exact(&realization.systemd_unit.unit_name, identity)
                    .await?;
                if !outcome.result.is_done() {
                    bail!("systemd stop job completed as {}", outcome.result.label());
                }
            }
            remove(
                &paths,
                &rendered,
                &bound.resource_spec.resource,
                &realization.systemd_unit.unit_name,
                bound.resource_spec.revision,
            )?;
            manager.daemon_reload().await?;
            inspect_absence(&manager, &expected, &realization, &paths).await?
        }
        InvocationPurpose::Reconcile if selected_method == "observe" => {
            if primary_method == "remove" {
                inspect_absence(&manager, &expected, &realization, &paths).await?
            } else {
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
        InvocationPurpose::Effect if selected_method == "remove" => inspection.complete,
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
    materialization_matches: bool,
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
    let files_before_manager_check = matches(
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
    let (state, manager_is_current) = if let Some(identity) = &unit_identity {
        let state = manager
            .active_state_exact(&realization.systemd_unit.unit_name, identity)
            .await?;
        let needs_reload = manager
            .needs_daemon_reload_exact(&realization.systemd_unit.unit_name, identity)
            .await?;
        (unit_state(state), !needs_reload)
    } else {
        (UnitState::Absent, false)
    };
    // Re-read the exact files after the manager property so a concurrent
    // replacement cannot pass by changing between the two observations.
    let files_after_manager_check = matches(
        paths,
        rendered,
        resource,
        &realization.systemd_unit.unit_name,
        revision,
    )?;
    let files_match = files_before_manager_check && files_after_manager_check;
    let activation_matches =
        realization.activation == Activation::Reference || state == UnitState::Active;
    let complete = files_match && manager_is_current && activation_matches;
    let mut discrepancies = Vec::new();
    if !files_match {
        discrepancies.push("drop_in".to_string());
    }
    if !manager_is_current {
        discrepancies.push("manager-reload".to_string());
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
        revision_matches: files_match && manager_is_current,
        materialization_matches: files_match,
        complete,
    })
}

async fn inspect_absence(
    manager: &PinnedSystemdManager,
    expected: &PackagedUnitRequest,
    realization: &PackagedUnitRealization,
    paths: &UnitPaths,
) -> Result<Inspection> {
    let files_absent_before_manager_check = is_absent(paths)?;
    let unit_identity = match manager
        .unit_identity(&realization.systemd_unit.unit_name)
        .await
    {
        Ok(identity) => Some(identity),
        Err(error) if error.is_no_such_unit() => None,
        Err(error) => return Err(error.into()),
    };
    let files_absent_after_manager_check = is_absent(paths)?;
    let files_absent = files_absent_before_manager_check && files_absent_after_manager_check;
    let manager_absent = unit_identity.is_none();
    let complete = files_absent && manager_absent;
    let mut discrepancies = Vec::new();
    if !files_absent {
        discrepancies.push("drop_in".to_string());
    }
    if !manager_absent {
        discrepancies.push("state".to_string());
    }

    Ok(Inspection {
        observation: PackagedUnitObservation {
            schema: OBSERVATION_SCHEMA.to_string(),
            expected: expected.clone(),
            observed: None,
            unit_name: realization.systemd_unit.unit_name.clone(),
            state: if manager_absent {
                UnitState::Absent
            } else {
                UnitState::Unknown
            },
            discrepancies,
        },
        unit_identity,
        revision_matches: false,
        materialization_matches: false,
        complete,
    })
}

fn provider_context(
    manager: &PinnedSystemdManager,
    unit_identity: Option<String>,
    unit_owned: bool,
) -> Result<AbilityValue> {
    value(&ProviderContext {
        schema: model::PROVIDER_CONTEXT_SCHEMA.to_string(),
        manager_bus_id: manager.incarnation().bus_id().to_string(),
        manager_owner: manager.incarnation().owner().to_string(),
        unit_identity,
        unit_owned,
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

fn require_prerequisite_contexts(
    prerequisites: &[aos_ability_model::ResourceReference],
    contexts: &[ResourceContext],
) -> Result<()> {
    for prerequisite in prerequisites {
        let matches = contexts
            .iter()
            .filter(|context| context.reference == *prerequisite)
            .count();
        if matches != 1 {
            bail!("packaged-unit prerequisite lacks one exact checked resource context");
        }
    }
    Ok(())
}

fn require_method(
    method: &aos_ability_model::MethodReference,
    semantics: &MethodSemantics,
) -> Result<()> {
    if method.interface.name.as_str() != INTERFACE_NAME {
        bail!("handler invocation selects another interface");
    }
    let expected = match method.method.as_str() {
        "apply" => MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
        "observe" => MethodSemantics::ordinary(AccessMode::Read),
        "remove" => MethodSemantics::provider_stop(),
        _ => bail!("handler invocation selects an unsupported method"),
    };
    if *semantics != expected {
        bail!("handler invocation carries mismatched method semantics");
    }
    Ok(())
}

fn require_target_revision(resource: RevisionId, context: RevisionId) -> Result<()> {
    if resource != context {
        bail!("target native context carries another semantic revision");
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
        .take(ABILITY_LIMITS_V1.max_document_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .context("reading handler input")?;
    let input_too_large = match u64::try_from(bytes.len()) {
        Ok(length) => length > ABILITY_LIMITS_V1.max_document_bytes,
        Err(_) => true,
    };
    if input_too_large {
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

#[cfg(test)]
mod tests {
    use aos_ability_model::{
        AbilityValue, AccessMode, MethodReference, MethodSemantics, ResourceReference, RevisionId,
    };
    use aos_contract::Sha256Digest;
    use aos_provider_protocol::ResourceContext;

    use super::{require_method, require_prerequisite_contexts, require_target_revision};

    fn method(name: &str) -> MethodReference {
        serde_json::from_value(serde_json::json!({
            "interface": {
                "name": "aos.systemd.packaged-unit",
                "abi": 1,
                "descriptor": Sha256Digest::from_bytes([1; 32]).to_string(),
            },
            "method": name,
        }))
        .expect("method fixture is valid")
    }

    #[test]
    fn methods_require_their_exact_declared_semantics() {
        let apply = method("apply");
        let observe = method("observe");
        let remove = method("remove");

        assert!(
            require_method(
                &apply,
                &MethodSemantics::ordinary(AccessMode::ExclusiveWrite)
            )
            .is_ok()
        );
        assert!(require_method(&observe, &MethodSemantics::ordinary(AccessMode::Read)).is_ok());
        assert!(require_method(&apply, &MethodSemantics::ordinary(AccessMode::Read)).is_err());
        assert!(require_method(&observe, &MethodSemantics::provider_stop()).is_err());
        assert!(require_method(&remove, &MethodSemantics::provider_stop()).is_ok());
        assert!(
            require_method(
                &remove,
                &MethodSemantics::ordinary(AccessMode::ExclusiveWrite)
            )
            .is_err()
        );
    }

    #[test]
    fn target_context_revision_must_equal_its_resource_specification() {
        let expected = RevisionId(Sha256Digest::from_bytes([1; 32]));
        let changed = RevisionId(Sha256Digest::from_bytes([2; 32]));

        assert!(require_target_revision(expected, expected).is_ok());
        assert!(require_target_revision(expected, changed).is_err());
    }

    fn resource_reference(key: &str) -> ResourceReference {
        serde_json::from_value(serde_json::json!({
            "interface": {
                "name": "aos.kernel.modules",
                "abi": 1,
                "descriptor": format!("sha256:{}", "1".repeat(64)),
            },
            "resource": {
                "provider": {
                    "environment": {
                        "authority": "test",
                        "key": "host",
                        "stage": "host",
                    },
                    "key": "kmod",
                },
                "key": key,
            },
            "operations": ["observe"],
            "lifetime": "instance",
        }))
        .expect("resource-reference fixture is valid")
    }

    fn context(reference: ResourceReference) -> ResourceContext {
        let empty =
            AbilityValue::new(serde_json::Value::Null).expect("null context fixture is bounded");
        ResourceContext {
            reference,
            revision: RevisionId(Sha256Digest::from_bytes([2; 32])),
            observation: empty.clone(),
            native_context: empty,
            native_context_digest: Sha256Digest::from_bytes([3; 32]),
        }
    }

    #[test]
    fn prerequisites_require_one_exact_checked_context() {
        let expected = resource_reference("configured");
        let changed = resource_reference("other");

        assert!(
            require_prerequisite_contexts(
                std::slice::from_ref(&expected),
                &[context(expected.clone())],
            )
            .is_ok()
        );
        assert!(require_prerequisite_contexts(std::slice::from_ref(&expected), &[]).is_err());
        assert!(
            require_prerequisite_contexts(std::slice::from_ref(&expected), &[context(changed)],)
                .is_err()
        );
        assert!(
            require_prerequisite_contexts(
                &[expected.clone()],
                &[context(expected.clone()), context(expected)],
            )
            .is_err()
        );
    }
}
