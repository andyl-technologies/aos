//! Package-owned systemd ability handler.
//!
//! The binary implements the bounded AOS provider protocol for package-shipped
//! units and provider-neutral services selected for systemd. It consumes exact
//! checked realizations, materializes their authenticated bytes, and drives a
//! pinned systemd manager over D-Bus.

mod identity;
mod manager_watchdog;
mod materialize;
mod model;
mod native_resource;
mod readiness;
mod render;
mod semantic;
mod service;
mod static_assemble;
mod static_render;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, AccessMode, LocalKey, MethodSemantics, ResourceReference,
};
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, HANDLER_ABI_ARGUMENT, INVOCATION_SCHEMA, Invocation,
    InvocationDisposition, InvocationPurpose, InvocationResult, REQUEST_SCHEMA, RESULT_SCHEMA,
    ResourceContext, SupportedPurposes, resource_set_digest, validate_admission_resource,
    validate_resource_context, validate_resource_contexts,
};
use aos_systemd::{PinnedSystemdManager, UnitActiveState};
use serde::Serialize;

use crate::materialize::{
    UnitPaths, is_absent, matches, materialize, paths_for, remove, validate_removal,
};
use crate::model::{
    Activation, OBSERVATION_SCHEMA, PackagedUnitEffectsRequest, PackagedUnitObservation,
    PackagedUnitRealization, PackagedUnitRequest, ProviderContext, UnitState, empty_outputs,
};
use crate::render::{RenderedUnit, render};

const ETC_ROOT: &str = "/etc";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HandlerRole {
    DevicePresence,
    Identity(identity::IdentityRole),
    ManagerWatchdog,
    NativeResource(native_resource::NativeResourceRole),
    PackagedUnit,
    Readiness(readiness::ReadinessRole),
    Service,
}

impl HandlerRole {
    fn from_entry_point(argument_zero: &OsStr) -> Result<Self> {
        let name = Path::new(argument_zero)
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| anyhow::anyhow!("handler entry point is not valid UTF-8"))?;

        match name {
            "aos-systemd-device-presence" => Ok(Self::DevicePresence),
            "aos-systemd-group-effects" => Ok(Self::Identity(identity::IdentityRole::Group)),
            "aos-systemd-group-membership-effects" => {
                Ok(Self::Identity(identity::IdentityRole::GroupMembership))
            }
            "aos-systemd-manager-watchdog-effects" => Ok(Self::ManagerWatchdog),
            "aos-systemd-mount-effects" => Ok(Self::NativeResource(
                native_resource::NativeResourceRole::Mount,
            )),
            "aos-systemd-packaged-unit-effects" => Ok(Self::PackagedUnit),
            "aos-systemd-principal-effects" => {
                Ok(Self::Identity(identity::IdentityRole::Principal))
            }
            "aos-systemd-scheduled-activation-effects" => Ok(Self::NativeResource(
                native_resource::NativeResourceRole::ScheduledActivation,
            )),
            "aos-systemd-service-effects" => Ok(Self::Service),
            "aos-systemd-swap-effects" => Ok(Self::NativeResource(
                native_resource::NativeResourceRole::Swap,
            )),
            "aos-systemd-network-readiness-effects" => {
                Ok(Self::Readiness(readiness::ReadinessRole::Network))
            }
            "aos-systemd-filesystem-readiness-effects" => {
                Ok(Self::Readiness(readiness::ReadinessRole::Filesystem))
            }
            "aos-systemd-activation-milestone-effects" => Ok(Self::Readiness(
                readiness::ReadinessRole::ActivationMilestone,
            )),
            "aos-systemd-runtime-entry-population-effects" => Ok(Self::Readiness(
                readiness::ReadinessRole::RuntimeEntryPopulation,
            )),
            "aos-systemd-system-milestone-readiness-effects" => {
                Ok(Self::Readiness(readiness::ReadinessRole::SystemMilestone))
            }
            _ => bail!("entry point does not select a checked systemd handler role"),
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("aos-systemd-provider: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments.len() == 2 && arguments[1] == "render" {
        return static_render::run();
    }
    if arguments.len() == 2 && arguments[1] == "assemble" {
        return static_assemble::run();
    }
    if arguments.len() != 3 || arguments[1] != HANDLER_ABI_ARGUMENT {
        bail!("expected --aos-primitive-v1 and one invocation purpose");
    }
    let role = HandlerRole::from_entry_point(&arguments[0])?;
    let bytes = read_input()?;
    match arguments[2].to_str() {
        Some("admit") => {
            let request: AdmissionRequest = decode_canonical(&bytes)?;
            let timeout = deadline(request.control.attempt_remaining_millis);
            let result = tokio::time::timeout(timeout, admit(role, request))
                .await
                .context("admission deadline expired")??;
            write_output(&result)
        }
        Some(purpose) => {
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
            let result = tokio::time::timeout(timeout, invoke(role, request))
                .await
                .context("invocation deadline expired")??;
            write_output(&result)
        }
        None => bail!("invocation purpose is not valid UTF-8"),
    }
}

async fn admit(role: HandlerRole, request: AdmissionRequest) -> Result<AdmissionResult> {
    match role {
        HandlerRole::DevicePresence => native_resource::admit_device_role(request).await,
        HandlerRole::Identity(role) => identity::admit(role, request).await,
        HandlerRole::ManagerWatchdog => manager_watchdog::admit(request).await,
        HandlerRole::NativeResource(role) => native_resource::admit(role, request).await,
        HandlerRole::PackagedUnit => admit_packaged_unit(request).await,
        HandlerRole::Readiness(role) => readiness::admit(role, request).await,
        HandlerRole::Service => service::admit(request).await,
    }
}

async fn admit_packaged_unit(request: AdmissionRequest) -> Result<AdmissionResult> {
    if request.schema != ADMISSION_REQUEST_SCHEMA {
        bail!("unsupported admission request schema");
    }
    validate_admission_resource(&request)?;
    require_method(&request.method, &request.semantics)?;
    validate_resource_contexts(&request.resources)?;

    let expected: PackagedUnitRequest = decode_value(&request.resource_spec.value)?;
    require_resource_contexts(&packaged_resource_references(&expected), &request.resources)?;
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
        incarnation: Some(request.assignment.incarnation),
        observation: packaged_effect_observation(&inspection.observation)?,
        native_context: provider_context,
        supported_purposes,
    })
}

async fn invoke(role: HandlerRole, invocation: Invocation) -> Result<InvocationResult> {
    match role {
        HandlerRole::DevicePresence => native_resource::invoke_device_role(invocation).await,
        HandlerRole::Identity(role) => identity::invoke(role, invocation).await,
        HandlerRole::ManagerWatchdog => manager_watchdog::invoke(invocation).await,
        HandlerRole::NativeResource(role) => native_resource::invoke(role, invocation).await,
        HandlerRole::PackagedUnit => invoke_packaged_unit(invocation).await,
        HandlerRole::Readiness(role) => readiness::invoke(role, invocation).await,
        HandlerRole::Service => service::invoke(invocation).await,
    }
}

async fn invoke_packaged_unit(invocation: Invocation) -> Result<InvocationResult> {
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
    validate_resource_contexts(&invocation.request.resources)?;

    let target = target_context(&invocation)?;
    let bound = validate_resource_context(target)?;
    let expected: PackagedUnitRequest = decode_value(&bound.resource_spec.value)?;
    require_resource_contexts(
        &packaged_resource_references(&expected),
        &invocation.request.resources,
    )?;
    let method_inputs: PackagedUnitEffectsRequest = decode_value(&invocation.request.inputs)?;
    if method_inputs.desired() != &expected {
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
        InvocationPurpose::Effect
            if matches!(selected_method, "create" | "reconcile" | "update") =>
        {
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
        InvocationPurpose::Effect
            if matches!(selected_method, "create" | "reconcile" | "update") =>
        {
            inspection.complete
        }
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
        outputs_for(&inspection.observation)?
    } else {
        empty_outputs()
    };
    Ok(InvocationResult {
        schema: RESULT_SCHEMA.to_string(),
        disposition,
        evidence: packaged_effect_observation(&inspection.observation)?,
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

fn outputs_for(observation: &PackagedUnitObservation) -> Result<BTreeMap<LocalKey, AbilityValue>> {
    let mut outputs = BTreeMap::new();
    outputs.insert(
        LocalKey::new("observation")?,
        packaged_effect_observation(observation)?,
    );
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

fn require_resource_contexts(
    prerequisites: &[aos_ability_model::ResourceReference],
    contexts: &[ResourceContext],
) -> Result<()> {
    for prerequisite in prerequisites {
        let matches = contexts
            .iter()
            .filter(|context| context.reference == *prerequisite)
            .count();
        if matches != 1 {
            bail!("provider input lacks one exact checked resource context");
        }
    }
    Ok(())
}

fn packaged_resource_references(request: &PackagedUnitRequest) -> Vec<ResourceReference> {
    let candidates = request
        .prerequisites
        .iter()
        .chain(&request.dependencies.after)
        .chain(&request.dependencies.before)
        .chain(&request.dependencies.requires)
        .chain(&request.dependencies.wants);
    let mut references = Vec::new();
    for reference in candidates {
        if !references.contains(reference) {
            references.push(reference.clone());
        }
    }
    references
}

fn require_method(
    method: &aos_ability_model::MethodReference,
    semantics: &MethodSemantics,
) -> Result<()> {
    let expected = match method.method.as_str() {
        "create" | "reconcile" | "update" => MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
        "observe" => MethodSemantics::ordinary(AccessMode::Read),
        "remove" => MethodSemantics::provider_stop(),
        _ => bail!("handler invocation selects an unsupported method"),
    };
    if *semantics != expected {
        bail!("handler invocation carries mismatched method semantics");
    }
    Ok(())
}

fn packaged_effect_observation(observation: &PackagedUnitObservation) -> Result<AbilityValue> {
    value(&serde_json::json!({
        "kind": "packaged-unit",
        "observation": observation,
    }))
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
    use std::ffi::OsStr;

    use aos_ability_model::{
        AbilityValue, AccessMode, MethodReference, MethodSemantics, ResourceReference, RevisionId,
    };
    use aos_contract::Sha256Digest;
    use aos_provider_protocol::ResourceContext;

    use super::{
        HandlerRole, packaged_resource_references, require_method, require_resource_contexts,
    };
    use crate::identity::IdentityRole;
    use crate::model::PackagedUnitRequest;
    use crate::native_resource::NativeResourceRole;
    use crate::readiness::ReadinessRole;

    fn method(name: &str) -> MethodReference {
        serde_json::from_value(serde_json::json!({
            "interface": {
                "name": "aos.systemd.packaged-unit-effects",
                "abi": 1,
                "descriptor": Sha256Digest::from_bytes([1; 32]).to_string(),
            },
            "method": name,
        }))
        .expect("method fixture is valid")
    }

    #[test]
    fn methods_require_their_exact_declared_semantics() {
        let apply = method("create");
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
    fn entry_points_select_closed_semantic_roles() {
        assert_eq!(
            HandlerRole::from_entry_point(OsStr::new(
                "/nix/store/provider/bin/aos-systemd-group-effects"
            ))
            .expect("group role parses"),
            HandlerRole::Identity(IdentityRole::Group)
        );
        assert_eq!(
            HandlerRole::from_entry_point(OsStr::new("aos-systemd-mount-effects"))
                .expect("mount role parses"),
            HandlerRole::NativeResource(NativeResourceRole::Mount)
        );
        assert_eq!(
            HandlerRole::from_entry_point(OsStr::new(
                "aos-systemd-system-milestone-readiness-effects",
            ))
            .expect("milestone role parses"),
            HandlerRole::Readiness(ReadinessRole::SystemMilestone)
        );
        assert!(
            HandlerRole::from_entry_point(OsStr::new("aos-systemd-provider")).is_err(),
            "the generic binary cannot select a runtime handler role",
        );
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
        let assignment = serde_json::from_value(serde_json::json!({
            "provider": reference.resource.provider.clone(),
            "interface": reference.interface.clone(),
            "implementation": {
                "descriptor": format!("sha256:{}", "4".repeat(64)),
                "artifact": {
                    "content": format!("sha256:{}", "5".repeat(64)),
                    "store_path": "/nix/store/00000000000000000000000000000000-provider",
                    "nar_hash": format!("sha256:{}", "6".repeat(64)),
                    "closure": format!("sha256:{}", "7".repeat(64)),
                },
                "handler": "test",
            },
            "incarnation": "test-incarnation",
        }))
        .expect("provider-assignment fixture is valid");
        ResourceContext {
            reference,
            assignment,
            revision: RevisionId(Sha256Digest::from_bytes([2; 32])),
            observation: empty.clone(),
            native_context: empty,
            native_context_digest: Sha256Digest::from_bytes([3; 32]),
        }
    }

    #[test]
    fn every_packaged_unit_reference_requires_one_exact_checked_context() {
        let expected = resource_reference("configured");
        let changed = resource_reference("other");

        assert!(
            require_resource_contexts(
                std::slice::from_ref(&expected),
                &[context(expected.clone())],
            )
            .is_ok()
        );
        assert!(require_resource_contexts(std::slice::from_ref(&expected), &[]).is_err());
        assert!(
            require_resource_contexts(std::slice::from_ref(&expected), &[context(changed)],)
                .is_err()
        );
        assert!(
            require_resource_contexts(
                &[expected.clone()],
                &[context(expected.clone()), context(expected)],
            )
            .is_err()
        );
    }

    #[test]
    fn packaged_unit_context_set_covers_native_dependencies() {
        let prerequisite = resource_reference("configured");
        let dependency = resource_reference("service");
        let request: PackagedUnitRequest = serde_json::from_value(serde_json::json!({
            "source": {
                "artifact": {
                    "content": format!("sha256:{}", "1".repeat(64)),
                    "store_path": "/nix/store/11111111111111111111111111111111-systemd",
                    "nar_hash": format!("sha256:{}", "2".repeat(64)),
                    "closure": format!("sha256:{}", "3".repeat(64)),
                },
                "unit_file": "lib/systemd/system/example.service",
                "unit_name": "example.service",
            },
            "activation": "reference",
            "prerequisites": [prerequisite.clone()],
            "dependencies": {
                "after": [dependency.clone()],
                "before": [],
                "requires": [dependency],
                "wants": [],
            },
            "drop_in": {
                "accepted_exit_statuses": [],
                "reload_triggers": [],
                "search_path": [],
            },
        }))
        .expect("packaged-unit request fixture is valid");

        let references = packaged_resource_references(&request);

        assert_eq!(references.len(), 2);
        assert_eq!(references[0], prerequisite);
    }
}
