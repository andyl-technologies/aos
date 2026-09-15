//! Native systemd realization of provider-neutral mount, swap, and device resources.

use std::path::{Component, Path};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use aos_ability_model::{
    AbilityValue, AccessMode, LocalKey, MethodReference, MethodSemantics, ResourceId,
    ResourceReference, RevisionId,
};
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, INVOCATION_SCHEMA, Invocation, InvocationDisposition,
    InvocationPurpose, InvocationResult, REQUEST_SCHEMA, RESULT_SCHEMA, SupportedPurposes,
    resource_set_digest, validate_admission_resource, validate_resource_context,
    validate_resource_contexts,
};
use aos_systemd::{PinnedSystemdManager, UnitActiveState};
use serde::{Deserialize, Serialize};

use crate::materialize::{
    ServicePaths, materialize_service, remove_service, service_is_absent, service_matches,
    service_paths_for,
};
use crate::model::{PROVIDER_CONTEXT_SCHEMA, ProviderContext};
use crate::render::{RenderedService, RenderedServiceLink, RenderedServiceUnit};
use crate::{decode_value, empty_outputs, provider_context, target_context, value};

const ETC_ROOT: &str = "/etc";
const MOUNT_EFFECTS_INTERFACE: &str = "aos.systemd.mount-effects";
const SWAP_EFFECTS_INTERFACE: &str = "aos.systemd.swap-effects";
const DEVICE_PRESENCE_INTERFACE: &str = "aos.device.presence";
const MOUNT_RESOURCE_KIND: &str = "aos.filesystem.mount";
const SWAP_RESOURCE_KIND: &str = "aos.memory.swap";
const REALIZATION_SCHEMA: &str = "aos.systemd.native-resource-realization/v1";
const MOUNT_OBSERVATION_SCHEMA: &str = "aos.ability.mount-resource-observation/v1";
const SWAP_OBSERVATION_SCHEMA: &str = "aos.ability.swap-resource-observation/v1";
const DEVICE_OBSERVATION_SCHEMA: &str = "aos.ability.device-presence-observation/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EffectRequest<T> {
    desired: T,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MountDesired {
    name: String,
    enabled: bool,
    source: String,
    destination: String,
    filesystem: Option<String>,
    options: Vec<String>,
    timeout_millis: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SwapDesired {
    name: String,
    enabled: bool,
    source: String,
    priority: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DeviceDesired {
    name: String,
    device: String,
    timeout_millis: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum NativeBackend {
    MountUnit,
    SwapUnit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct NativeRealization {
    schema: String,
    backend: NativeBackend,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct StaticNativeResource {
    pub(crate) schema: String,
    pub(crate) kind: String,
    pub(crate) desired: AbilityValue,
    pub(crate) realization: AbilityValue,
}

enum Desired {
    Mount(MountDesired),
    Swap(SwapDesired),
}

impl Desired {
    fn enabled(&self) -> bool {
        match self {
            Self::Mount(desired) => desired.enabled,
            Self::Swap(desired) => desired.enabled,
        }
    }

    fn resource_kind(&self) -> &'static str {
        match self {
            Self::Mount(_) => MOUNT_RESOURCE_KIND,
            Self::Swap(_) => SWAP_RESOURCE_KIND,
        }
    }

    fn observation_schema(&self) -> &'static str {
        match self {
            Self::Mount(_) => MOUNT_OBSERVATION_SCHEMA,
            Self::Swap(_) => SWAP_OBSERVATION_SCHEMA,
        }
    }
}

pub(crate) fn supports(method: &MethodReference) -> bool {
    matches!(
        method.interface.name.as_str(),
        MOUNT_EFFECTS_INTERFACE | SWAP_EFFECTS_INTERFACE | DEVICE_PRESENCE_INTERFACE
    )
}

pub(crate) async fn admit(request: AdmissionRequest) -> Result<AdmissionResult> {
    if request.schema != ADMISSION_REQUEST_SCHEMA {
        bail!("unsupported native-resource admission request schema");
    }
    validate_admission_resource(&request)?;
    validate_resource_contexts(&request.resources)?;
    require_method(&request.method, &request.semantics)?;

    if request.method.interface.name.as_str() == DEVICE_PRESENCE_INTERFACE {
        return admit_device(request).await;
    }

    let desired = desired_from_value(&request.method, &request.resource_spec.value)?;
    require_realization(&desired, &request.resource_spec.realization)?;
    if request.resource_spec.kind.as_str() != desired.resource_kind() {
        bail!("native-resource desired value differs from its resource kind");
    }
    let rendered = render(&desired)?;
    let paths = service_paths_for(
        Path::new(ETC_ROOT),
        &rendered.primary_unit,
        request.resource_spec.revision,
        &rendered,
    );
    let manager = PinnedSystemdManager::connect().await?;
    let inspection = inspect(
        &manager,
        &desired,
        &request.resource_spec.value,
        &request.target,
        &request.resource_spec.resource,
        request.resource_spec.revision,
        &rendered,
        &paths,
        Goal::Desired,
    )
    .await?;
    let context = provider_context(
        &manager,
        inspection.unit_identity.clone(),
        inspection.files_match,
    )?;

    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.to_string(),
        disposition: AdmissionDisposition::Admitted,
        revision: if inspection.complete {
            AdmissionRevision::Present {
                revision: request.resource_spec.revision,
            }
        } else {
            AdmissionRevision::Absent
        },
        incarnation: Some(request.assignment.incarnation),
        observation: effect_observation(&desired, &inspection.observation)?,
        native_context: context,
        supported_purposes: supported_purposes()?,
    })
}

pub(crate) async fn invoke(invocation: Invocation) -> Result<InvocationResult> {
    if invocation.schema != INVOCATION_SCHEMA || invocation.request.schema != REQUEST_SCHEMA {
        bail!("unsupported native-resource invocation schema");
    }
    if !invocation.method_is_bound() {
        bail!("native-resource invocation method is not bound to its recovery contract");
    }
    if resource_set_digest(&invocation.request.resources)?
        != invocation.request.native_context_digest
    {
        bail!("native-resource invocation resource-set digest does not match");
    }
    validate_resource_contexts(&invocation.request.resources)?;
    require_method(&invocation.method, &invocation.semantics)?;
    require_method(&invocation.request.method, &invocation.request.semantics)?;

    if invocation.method.interface.name.as_str() == DEVICE_PRESENCE_INTERFACE {
        return invoke_device(invocation).await;
    }
    if invocation.method.interface != invocation.request.method.interface {
        bail!("native-resource recovery cannot cross effect interfaces");
    }

    let bound = validate_resource_context(target_context(&invocation)?)?;
    let desired = desired_from_value(&invocation.method, &bound.resource_spec.value)?;
    require_inputs(&desired, &invocation.request.inputs)?;
    require_realization(&desired, &bound.resource_spec.realization)?;
    if bound.resource_spec.kind.as_str() != desired.resource_kind() {
        bail!("native-resource desired value differs from its resource kind");
    }
    let provider: ProviderContext = decode_value(&bound.provider_context)?;
    if provider.schema != PROVIDER_CONTEXT_SCHEMA {
        bail!("unsupported native-resource provider context schema");
    }

    let rendered = render(&desired)?;
    let paths = service_paths_for(
        Path::new(ETC_ROOT),
        &rendered.primary_unit,
        bound.resource_spec.revision,
        &rendered,
    );
    let manager = PinnedSystemdManager::connect().await?;
    require_manager(&manager, &provider)?;

    let removing = invocation.request.method.method.as_str() == "remove";
    if invocation.purpose == InvocationPurpose::Effect {
        match invocation.method.method.as_str() {
            "create" | "reconcile" | "update" => {
                apply(
                    &manager,
                    &desired,
                    &bound.resource_spec.resource,
                    bound.resource_spec.revision,
                    &rendered,
                    &paths,
                )
                .await?;
            }
            "remove" => {
                release(
                    &manager,
                    &bound.resource_spec.resource,
                    bound.resource_spec.revision,
                    &rendered,
                    &paths,
                )
                .await?;
            }
            "observe" => {}
            _ => bail!("unsupported native-resource effect method"),
        }
    } else if invocation.purpose != InvocationPurpose::Reconcile
        || invocation.method.method.as_str() != "observe"
    {
        bail!("native-resource provider does not advertise this invocation purpose");
    }

    let reference = observed_reference(&target_context(&invocation)?.reference)?;
    let inspection = inspect(
        &manager,
        &desired,
        &bound.resource_spec.value,
        &reference,
        &bound.resource_spec.resource,
        bound.resource_spec.revision,
        &rendered,
        &paths,
        if removing {
            Goal::Absent
        } else {
            Goal::Desired
        },
    )
    .await?;
    let evidence = effect_observation(&desired, &inspection.observation)?;
    let mut outputs = empty_outputs();
    if inspection.complete {
        outputs.insert(LocalKey::new("observation")?, evidence.clone());
    }

    Ok(InvocationResult {
        schema: RESULT_SCHEMA.to_string(),
        disposition: if inspection.complete {
            InvocationDisposition::Completed
        } else {
            InvocationDisposition::SafeToRetry
        },
        evidence,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

async fn admit_device(request: AdmissionRequest) -> Result<AdmissionResult> {
    if !request.resource_spec.realization.as_json().is_null() {
        bail!("device-presence observation unexpectedly carries a realization");
    }
    let desired: DeviceDesired = decode_value(&request.resource_spec.value)?;
    let manager = PinnedSystemdManager::connect().await?;
    let inspection = inspect_device(&manager, &desired).await?;

    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.to_string(),
        disposition: AdmissionDisposition::Admitted,
        revision: if inspection.ready {
            AdmissionRevision::Present {
                revision: request.resource_spec.revision,
            }
        } else {
            AdmissionRevision::Absent
        },
        incarnation: Some(request.assignment.incarnation),
        observation: inspection.observation,
        native_context: provider_context(&manager, inspection.unit_identity, false)?,
        supported_purposes: supported_purposes()?,
    })
}

async fn invoke_device(invocation: Invocation) -> Result<InvocationResult> {
    if invocation.method.interface != invocation.request.method.interface {
        bail!("device-presence recovery cannot cross interfaces");
    }
    if !matches!(
        invocation.purpose,
        InvocationPurpose::Effect | InvocationPurpose::Reconcile
    ) {
        bail!("device-presence provider does not advertise this invocation purpose");
    }

    let bound = validate_resource_context(target_context(&invocation)?)?;
    if !bound.resource_spec.realization.as_json().is_null() {
        bail!("device-presence observation unexpectedly carries a realization");
    }
    if invocation.request.inputs != bound.resource_spec.value {
        bail!("device-presence inputs differ from the checked desired value");
    }
    let desired: DeviceDesired = decode_value(&bound.resource_spec.value)?;
    let provider: ProviderContext = decode_value(&bound.provider_context)?;
    if provider.schema != PROVIDER_CONTEXT_SCHEMA {
        bail!("unsupported device-presence provider context schema");
    }
    let manager = PinnedSystemdManager::connect().await?;
    require_manager(&manager, &provider)?;

    let budget = desired
        .timeout_millis
        .unwrap_or(0)
        .min(invocation.control.attempt_remaining_millis);
    let inspection = wait_for_device(&manager, &desired, Duration::from_millis(budget)).await?;
    let mut outputs = empty_outputs();
    outputs.insert(
        LocalKey::new("observation")?,
        inspection.observation.clone(),
    );
    if inspection.ready {
        outputs.insert(LocalKey::new("device-node")?, value(&desired.device)?);
    }

    Ok(InvocationResult {
        schema: RESULT_SCHEMA.to_string(),
        disposition: if inspection.ready {
            InvocationDisposition::Completed
        } else {
            InvocationDisposition::SafeToRetry
        },
        evidence: inspection.observation,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

fn supported_purposes() -> Result<SupportedPurposes> {
    SupportedPurposes::from_ordered(vec![
        InvocationPurpose::Effect,
        InvocationPurpose::Reconcile,
    ])
    .ok_or_else(|| anyhow::anyhow!("native-resource purpose set is not canonical"))
}

fn require_method(method: &MethodReference, semantics: &MethodSemantics) -> Result<()> {
    if !supports(method) {
        bail!("native-resource method selects another interface");
    }
    let expected = if method.interface.name.as_str() == DEVICE_PRESENCE_INTERFACE {
        if method.method.as_str() != "observe" {
            bail!("device-presence handler exposes only observation");
        }
        MethodSemantics::ordinary(AccessMode::Read)
    } else {
        match method.method.as_str() {
            "observe" => MethodSemantics::ordinary(AccessMode::Read),
            "create" | "reconcile" | "update" => {
                MethodSemantics::ordinary(AccessMode::ExclusiveWrite)
            }
            "remove" => MethodSemantics::provider_stop(),
            _ => bail!("unsupported native-resource effect method"),
        }
    };
    if *semantics != expected {
        bail!("native-resource method carries mismatched semantics");
    }
    Ok(())
}

fn desired_from_value(method: &MethodReference, value: &AbilityValue) -> Result<Desired> {
    match method.interface.name.as_str() {
        MOUNT_EFFECTS_INTERFACE => Ok(Desired::Mount(decode_value(value)?)),
        SWAP_EFFECTS_INTERFACE => Ok(Desired::Swap(decode_value(value)?)),
        _ => bail!("native-resource effect selects an unsupported desired value"),
    }
}

fn require_inputs(desired: &Desired, inputs: &AbilityValue) -> Result<()> {
    let matches = match desired {
        Desired::Mount(value) => {
            decode_value::<EffectRequest<MountDesired>>(inputs)?.desired == *value
        }
        Desired::Swap(value) => {
            decode_value::<EffectRequest<SwapDesired>>(inputs)?.desired == *value
        }
    };
    if !matches {
        bail!("native-resource effect inputs differ from the checked desired resource");
    }
    Ok(())
}

fn require_realization(desired: &Desired, value: &AbilityValue) -> Result<()> {
    let realization: NativeRealization = decode_value(value)?;
    let expected = match desired {
        Desired::Mount(_) => NativeBackend::MountUnit,
        Desired::Swap(_) => NativeBackend::SwapUnit,
    };
    if realization.schema != REALIZATION_SCHEMA || realization.backend != expected {
        bail!("native resource uses an unsupported realization");
    }
    Ok(())
}

pub(crate) fn render_static(input: StaticNativeResource) -> Result<RenderedService> {
    if input.schema != "aos.systemd.native-resource-static-input/v1" {
        bail!("unsupported static native-resource input schema");
    }
    let desired = match input.kind.as_str() {
        MOUNT_RESOURCE_KIND => Desired::Mount(decode_value(&input.desired)?),
        SWAP_RESOURCE_KIND => Desired::Swap(decode_value(&input.desired)?),
        _ => bail!("static native-resource input selects an unsupported resource kind"),
    };
    require_realization(&desired, &input.realization)?;
    render(&desired)
}

fn render(desired: &Desired) -> Result<RenderedService> {
    let (unit_name, bytes, target) = match desired {
        Desired::Mount(mount) => {
            validate_absolute_path(&mount.source, "mount source")?;
            validate_absolute_path(&mount.destination, "mount destination")?;
            validate_lines(&mount.options, "mount option")?;
            let unit_name = path_unit_name(&mount.destination, "mount")?;
            let mut document = format!(
                "[Unit]\nDescription=AOS mount resource {}\n\n[Mount]\nWhat={}\nWhere={}\n",
                mount.name, mount.source, mount.destination
            );
            if let Some(filesystem) = &mount.filesystem {
                reject_line_break(filesystem, "mount filesystem")?;
                document.push_str(&format!("Type={filesystem}\n"));
            }
            if !mount.options.is_empty() {
                document.push_str(&format!("Options={}\n", mount.options.join(",")));
            }
            if let Some(timeout) = mount.timeout_millis {
                document.push_str(&format!("TimeoutSec={}ms\n", timeout));
            }
            (unit_name, document.into_bytes(), "local-fs.target")
        }
        Desired::Swap(swap) => {
            validate_absolute_path(&swap.source, "swap source")?;
            let unit_name = path_unit_name(&swap.source, "swap")?;
            let mut document = format!(
                "[Unit]\nDescription=AOS swap resource {}\n\n[Swap]\nWhat={}\n",
                swap.name, swap.source
            );
            if let Some(priority) = swap.priority {
                document.push_str(&format!("Priority={priority}\n"));
            }
            (unit_name, document.into_bytes(), "swap.target")
        }
    };
    let links = if desired.enabled() {
        vec![RenderedServiceLink {
            path: format!("{target}.wants/{unit_name}"),
            target: format!("../{unit_name}"),
        }]
    } else {
        Vec::new()
    };
    Ok(RenderedService {
        primary_unit: unit_name.clone(),
        units: vec![RenderedServiceUnit {
            name: unit_name,
            bytes,
        }],
        links,
    })
}

async fn apply(
    manager: &PinnedSystemdManager,
    desired: &Desired,
    resource: &ResourceId,
    revision: RevisionId,
    rendered: &RenderedService,
    paths: &ServicePaths,
) -> Result<()> {
    materialize_service(
        Path::new(ETC_ROOT),
        &rendered.primary_unit,
        revision,
        resource,
        rendered,
    )?;
    manager.daemon_reload().await?;
    let identity = manager.load_unit(&rendered.primary_unit).await?;
    let active = manager
        .active_state_exact(&rendered.primary_unit, &identity)
        .await?
        .is_active();
    if desired.enabled() && !active {
        let outcome = manager
            .start_unit_exact_current(&rendered.primary_unit, &identity)
            .await?;
        if !outcome.result.is_done() {
            bail!(
                "systemd native-resource start completed as {}",
                outcome.result.label()
            );
        }
    } else if !desired.enabled() && active {
        let outcome = manager
            .stop_unit_exact(&rendered.primary_unit, &identity)
            .await?;
        if !outcome.result.is_done() {
            bail!(
                "systemd native-resource stop completed as {}",
                outcome.result.label()
            );
        }
    }
    if !service_matches(paths, rendered, resource, revision)? {
        bail!("native-resource materialization changed during activation");
    }
    Ok(())
}

async fn release(
    manager: &PinnedSystemdManager,
    resource: &ResourceId,
    revision: RevisionId,
    rendered: &RenderedService,
    paths: &ServicePaths,
) -> Result<()> {
    let identity = match manager.unit_identity(&rendered.primary_unit).await {
        Ok(identity) => Some(identity),
        Err(error) if error.is_no_such_unit() => None,
        Err(error) => return Err(error.into()),
    };
    if let Some(identity) = identity
        && manager
            .active_state_exact(&rendered.primary_unit, &identity)
            .await?
            .is_active()
    {
        let outcome = manager
            .stop_unit_exact(&rendered.primary_unit, &identity)
            .await?;
        if !outcome.result.is_done() {
            bail!(
                "systemd native-resource stop completed as {}",
                outcome.result.label()
            );
        }
    }
    remove_service(paths, rendered, resource, revision)?;
    manager.daemon_reload().await?;
    Ok(())
}

enum Goal {
    Desired,
    Absent,
}

struct Inspection {
    observation: AbilityValue,
    unit_identity: Option<String>,
    files_match: bool,
    complete: bool,
}

#[allow(clippy::too_many_arguments)]
async fn inspect(
    manager: &PinnedSystemdManager,
    desired: &Desired,
    expected: &AbilityValue,
    reference: &ResourceReference,
    resource: &ResourceId,
    revision: RevisionId,
    rendered: &RenderedService,
    paths: &ServicePaths,
    goal: Goal,
) -> Result<Inspection> {
    let files_before = service_matches(paths, rendered, resource, revision)?;
    let absent_before = service_is_absent(paths)?;
    let unit_identity = match manager.unit_identity(&rendered.primary_unit).await {
        Ok(identity) => Some(identity),
        Err(error) if error.is_no_such_unit() => None,
        Err(error) => return Err(error.into()),
    };
    let (active_state, manager_current) = if let Some(identity) = &unit_identity {
        (
            Some(
                manager
                    .active_state_exact(&rendered.primary_unit, identity)
                    .await?,
            ),
            !manager
                .needs_daemon_reload_exact(&rendered.primary_unit, identity)
                .await?,
        )
    } else {
        (None, false)
    };
    let files_match = files_before && service_matches(paths, rendered, resource, revision)?;
    let files_absent = absent_before && service_is_absent(paths)?;
    let active = active_state
        .as_ref()
        .is_some_and(UnitActiveState::is_active);
    let failed = matches!(active_state, Some(UnitActiveState::Failed));
    let state_matches = active == desired.enabled();
    let complete = match goal {
        Goal::Desired => files_match && manager_current && state_matches,
        Goal::Absent => files_absent && !active,
    };
    let state = if complete && matches!(goal, Goal::Absent) {
        "absent"
    } else if failed {
        "failed"
    } else if complete {
        "ready"
    } else {
        "unknown"
    };
    let realized = if complete && matches!(goal, Goal::Desired) {
        Some(observed_reference(reference)?)
    } else {
        None
    };
    let observation = value(&serde_json::json!({
        "schema": desired.observation_schema(),
        "expected": expected.as_json(),
        "realized": realized,
        "state": state,
    }))?;

    Ok(Inspection {
        observation,
        unit_identity,
        files_match,
        complete,
    })
}

struct DeviceInspection {
    observation: AbilityValue,
    unit_identity: Option<String>,
    ready: bool,
}

async fn inspect_device(
    manager: &PinnedSystemdManager,
    desired: &DeviceDesired,
) -> Result<DeviceInspection> {
    validate_absolute_path(&desired.device, "device path")?;
    let unit_name = path_unit_name(&desired.device, "device")?;
    let unit_identity = match manager.unit_identity(&unit_name).await {
        Ok(identity) => Some(identity),
        Err(error) if error.is_no_such_unit() => None,
        Err(error) => return Err(error.into()),
    };
    let state = if let Some(identity) = &unit_identity {
        manager.active_state_exact(&unit_name, identity).await?
    } else {
        UnitActiveState::Inactive
    };
    let ready = state.is_active();
    let observed = ready.then_some(desired.device.as_str());
    let state = if ready {
        "ready"
    } else if state == UnitActiveState::Failed {
        "failed"
    } else if unit_identity.is_none() {
        "absent"
    } else {
        "unknown"
    };
    let observation = value(&serde_json::json!({
        "schema": DEVICE_OBSERVATION_SCHEMA,
        "expected": desired,
        "realized": observed,
        "state": state,
    }))?;

    Ok(DeviceInspection {
        observation,
        unit_identity,
        ready,
    })
}

async fn wait_for_device(
    manager: &PinnedSystemdManager,
    desired: &DeviceDesired,
    budget: Duration,
) -> Result<DeviceInspection> {
    let deadline = Instant::now() + budget;
    loop {
        let inspection = inspect_device(manager, desired).await?;
        if inspection.ready || Instant::now() >= deadline {
            return Ok(inspection);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn require_manager(manager: &PinnedSystemdManager, provider: &ProviderContext) -> Result<()> {
    if manager.incarnation().bus_id() != provider.manager_bus_id
        || manager.incarnation().owner() != provider.manager_owner
    {
        bail!("systemd manager changed after native-resource admission");
    }
    Ok(())
}

fn effect_observation(desired: &Desired, observation: &AbilityValue) -> Result<AbilityValue> {
    value(&serde_json::json!({
        "kind": desired.resource_kind(),
        "observation": observation.as_json(),
    }))
}

fn observed_reference(reference: &ResourceReference) -> Result<ResourceReference> {
    let mut reference = reference.clone();
    reference.operations = vec![LocalKey::new("observe")?];
    Ok(reference)
}

fn validate_absolute_path(path: &str, field: &str) -> Result<()> {
    reject_line_break(path, field)?;
    let path = Path::new(path);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        bail!("{field} is not a canonical absolute path");
    }
    Ok(())
}

fn validate_lines(values: &[String], field: &str) -> Result<()> {
    for value in values {
        reject_line_break(value, field)?;
    }
    Ok(())
}

fn reject_line_break(value: &str, field: &str) -> Result<()> {
    if value
        .bytes()
        .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r'))
    {
        bail!("{field} contains a unit-document line break");
    }
    Ok(())
}

fn path_unit_name(path: &str, suffix: &str) -> Result<String> {
    validate_absolute_path(path, "systemd path-unit source")?;
    let path = path.strip_prefix('/').unwrap_or(path);
    let escaped = if path.is_empty() {
        "-".to_string()
    } else {
        let mut escaped = String::new();
        for byte in path.bytes() {
            match byte {
                b'/' => escaped.push('-'),
                byte if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':') => {
                    escaped.push(char::from(byte));
                }
                byte => escaped.push_str(&format!("\\x{byte:02x}")),
            }
        }
        escaped
    };
    let unit_name = format!("{escaped}.{suffix}");
    if unit_name.len() > 255 {
        bail!("systemd path-unit name exceeds its bounded length");
    }
    Ok(unit_name)
}

#[cfg(test)]
mod tests {
    use super::{Desired, MountDesired, SwapDesired, path_unit_name, render};

    #[test]
    fn path_unit_names_follow_systemd_path_escaping() {
        assert_eq!(path_unit_name("/", "mount").expect("root path"), "-.mount");
        assert_eq!(
            path_unit_name("/dev/disk/by-partlabel/aos-swap", "swap").expect("device path"),
            "dev-disk-by\\x2dpartlabel-aos\\x2dswap.swap"
        );
        assert!(path_unit_name("relative", "mount").is_err());
        assert!(path_unit_name("/tmp/../escape", "mount").is_err());
    }

    #[test]
    fn mount_and_swap_render_exact_native_units() {
        let mount = Desired::Mount(MountDesired {
            name: "esp".to_string(),
            enabled: true,
            source: "/dev/disk/by-partlabel/ESP".to_string(),
            destination: "/boot".to_string(),
            filesystem: Some("vfat".to_string()),
            options: vec!["umask=0077".to_string()],
            timeout_millis: Some(30_000),
        });
        let rendered = render(&mount).expect("mount renders");
        assert_eq!(rendered.primary_unit, "boot.mount");
        assert_eq!(rendered.links[0].path, "local-fs.target.wants/boot.mount");
        assert_eq!(
            String::from_utf8(rendered.units[0].bytes.clone()).expect("unit is utf-8"),
            "[Unit]\nDescription=AOS mount resource esp\n\n[Mount]\nWhat=/dev/disk/by-partlabel/ESP\nWhere=/boot\nType=vfat\nOptions=umask=0077\nTimeoutSec=30000ms\n"
        );

        let swap = Desired::Swap(SwapDesired {
            name: "main".to_string(),
            enabled: true,
            source: "/dev/zram0".to_string(),
            priority: Some(100),
        });
        let rendered = render(&swap).expect("swap renders");
        assert_eq!(rendered.primary_unit, "dev-zram0.swap");
        assert_eq!(
            String::from_utf8(rendered.units[0].bytes.clone()).expect("unit is utf-8"),
            "[Unit]\nDescription=AOS swap resource main\n\n[Swap]\nWhat=/dev/zram0\nPriority=100\n"
        );
    }

    #[test]
    fn native_unit_fields_cannot_inject_directives() {
        let mount = Desired::Mount(MountDesired {
            name: "bad".to_string(),
            enabled: true,
            source: "/dev/example".to_string(),
            destination: "/mnt/example".to_string(),
            filesystem: None,
            options: vec!["rw\nExecStart=/wrong".to_string()],
            timeout_millis: None,
        });
        assert!(render(&mount).is_err());
    }
}
