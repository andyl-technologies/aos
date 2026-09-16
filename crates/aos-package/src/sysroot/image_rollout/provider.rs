//! Package-owned command handler for checked single-host image rollouts.
//!
//! The generic dispatcher authenticates the executable and protocol envelope.
//! This module owns the rollout-specific request, state, and host effects.

use std::collections::BTreeMap;
use std::io::{self, Read as _, Write as _};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::{ABILITY_LIMITS_V1, AbilityValue, LocalKey};
use aos_ability_runtime::adapter::RuntimeControl;
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, HANDLER_ABI_ARGUMENT, INVOCATION_SCHEMA, Invocation,
    InvocationControl, InvocationDisposition, InvocationPurpose, InvocationResult, RESULT_SCHEMA,
    SupportedPurposes, resource_set_digest, validate_admission_resource, validate_resource_context,
    validate_resource_contexts,
};

use super::ability::{AbilityRolloutOutcome, AbilityRolloutPhase, AbilityRolloutState};
use super::process::run_bounded_command;
use super::{ImageRolloutRequest, ImageRolloutTerminalRequest, NativeImageRolloutBackend};

const OBSERVATION_SCHEMA: &str = "aos.ability.image-rollout-observation/v1";
const PROVIDER_CONTEXT_SCHEMA: &str = "aos.image-rollout.provider-context/v1";
const REALIZATION_SCHEMA: &str = "aos.image-rollout.realization/v1";
const IMAGE_PROFILE: &str = "/var/lib/profiles/image";

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RolloutRealization {
    schema: String,
    #[serde(rename = "health-command")]
    health_command: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderContext {
    schema: String,
    image_profile: String,
    health_command: String,
}

/// Runs one image-rollout provider request from process arguments and streams.
///
/// # Errors
///
/// Returns an error when the protocol envelope, checked authority, rollout
/// request, native state, or bounded host effect is invalid.
pub fn run_from_process() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    ensure!(
        arguments.len() == 2 && arguments[0] == HANDLER_ABI_ARGUMENT,
        "expected --aos-primitive-v1 and one purpose"
    );

    let mut input = Vec::new();
    io::stdin()
        .take(ABILITY_LIMITS_V1.max_document_bytes + 1)
        .read_to_end(&mut input)
        .context("reading image-rollout handler request")?;
    ensure!(
        input.len() as u64 <= ABILITY_LIMITS_V1.max_document_bytes,
        "image-rollout handler request exceeds the canonical document bound"
    );

    let output = match arguments[1].as_str() {
        "admit" => serde_json::to_vec(&admit(serde_json::from_slice(&input)?)?)?,
        "effect" | "reconcile" | "cancel" => {
            let invocation = serde_json::from_slice(&input)?;
            serde_json::to_vec(&invoke(invocation, &arguments[1])?)?
        }
        _ => anyhow::bail!("unsupported image-rollout provider purpose"),
    };
    io::stdout()
        .write_all(&output)
        .context("writing image-rollout handler result")?;
    Ok(())
}

fn admit(request: AdmissionRequest) -> Result<AdmissionResult> {
    ensure!(
        request.schema == ADMISSION_REQUEST_SCHEMA,
        "admission schema differs from the selected ABI"
    );
    validate_admission_resource(&request)?;
    validate_resource_contexts(&request.resources)?;
    validate_method(&request.method)?;

    let desired: ImageRolloutRequest = decode_value(&request.resource_spec.value)?;
    let realization: RolloutRealization = decode_value(&request.resource_spec.realization)?;
    ensure!(
        realization.schema == REALIZATION_SCHEMA,
        "unsupported image-rollout realization schema"
    );
    let backend = backend();
    let observed = backend.observe_operation(&desired, request.method.method.as_str());
    let (revision, observation) = match observed {
        Ok(state) => (
            AdmissionRevision::Present {
                revision: request.resource_spec.revision,
            },
            observation(&state)?,
        ),
        Err(_error) if request.method.method.as_str() == "retain" => {
            backend
                .preflight_operation(&desired, "retain", system_now_millis())
                .context("preflighting an absent rollout")?;
            (AdmissionRevision::Absent, absent_observation(&desired)?)
        }
        Err(error) => return Err(error.context("observing admitted image rollout")),
    };

    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.into(),
        disposition: AdmissionDisposition::Admitted,
        revision,
        incarnation: Some(request.assignment.incarnation),
        observation,
        native_context: ability_value(serde_json::to_value(ProviderContext {
            schema: PROVIDER_CONTEXT_SCHEMA.into(),
            image_profile: IMAGE_PROFILE.into(),
            health_command: realization.health_command,
        })?)?,
        supported_purposes: SupportedPurposes::from_ordered(vec![
            InvocationPurpose::Effect,
            InvocationPurpose::Reconcile,
            InvocationPurpose::Cancel,
        ])
        .context("image-rollout purpose set is not canonical")?,
    })
}

fn invoke(invocation: Invocation, purpose: &str) -> Result<InvocationResult> {
    ensure!(
        invocation.schema == INVOCATION_SCHEMA
            && purpose == purpose_name(invocation.purpose)
            && invocation.method_is_bound(),
        "invocation envelope differs from the selected ABI"
    );
    validate_method(&invocation.method)?;
    validate_method(&invocation.request.method)?;
    validate_resource_contexts(&invocation.request.resources)?;
    ensure!(
        resource_set_digest(&invocation.request.resources)?
            == invocation.request.native_context_digest,
        "rollout resource set differs from its authenticated digest"
    );

    let target = invocation
        .request
        .resources
        .iter()
        .find(|resource| resource.reference.resource == invocation.request.target.resource)
        .context("rollout target context is absent")?;
    let bound = validate_resource_context(target)?;
    let realization: RolloutRealization = decode_value(&bound.resource_spec.realization)?;
    let provider: ProviderContext = decode_value(&bound.provider_context)?;
    ensure!(
        realization.schema == REALIZATION_SCHEMA
            && provider.schema == PROVIDER_CONTEXT_SCHEMA
            && provider.image_profile == IMAGE_PROFILE
            && provider.health_command == realization.health_command,
        "rollout provider context differs from the checked realization"
    );
    let terminal: ImageRolloutTerminalRequest = decode_value(&invocation.request.inputs)?;
    ensure!(
        ability_value(serde_json::to_value(&terminal.rollout)?)? == bound.resource_spec.value,
        "rollout inputs differ from the admitted resource value"
    );
    ensure!(
        target.reference == invocation.request.target
            && invocation.method.interface == invocation.request.method.interface
            && invocation.method.interface == invocation.request.target.interface
            && invocation
                .request
                .target
                .operations
                .binary_search(&invocation.method.method)
                .is_ok(),
        "rollout target authority differs from its admitted context"
    );
    let desired = terminal.rollout;
    let control = WireControl(&invocation.control);
    let original_method = invocation.request.method.method.as_str();

    if invocation.control.cancelled && invocation.purpose == InvocationPurpose::Effect {
        return result(
            &invocation,
            absent_observation(&desired)?,
            InvocationDisposition::RejectedBeforeEffect,
            BTreeMap::new(),
        );
    }

    match invocation.purpose {
        InvocationPurpose::Effect => execute(
            &invocation,
            &desired,
            terminal.entry.as_deref(),
            terminal.platform.as_ref(),
            original_method,
            &provider,
            &control,
        ),
        InvocationPurpose::Reconcile => {
            reconcile(&invocation, &desired, original_method, &provider, &control)
        }
        InvocationPurpose::Cancel => cancel(&invocation, &desired, original_method, &control),
        InvocationPurpose::Compensate | InvocationPurpose::ReconcileCompensation => {
            anyhow::bail!("image-rollout provider does not implement compensation")
        }
    }
}

fn execute(
    invocation: &Invocation,
    request: &ImageRolloutRequest,
    entry: Option<&str>,
    platform: Option<&serde_json::Value>,
    method: &str,
    provider: &ProviderContext,
    control: &dyn RuntimeControl,
) -> Result<InvocationResult> {
    let backend = backend();
    backend
        .preflight_operation(request, method, system_now_millis())
        .context("preflighting image-rollout effect")?;

    let state = match method {
        "retain" => {
            ensure!(
                platform.is_some(),
                "rollout retention lacks boot-storage evidence"
            );
            backend.retain(request)
        }
        "prepare" => backend.prepare(request),
        "drain" => backend.drain(request),
        "select" => backend.select(
            request,
            entry.context("rollout selection lacks a provider-resolved boot entry")?,
        ),
        "observe-boot" => backend.reconcile(request),
        "observe-health" => observe_health(&backend, request, &provider.health_command, control),
        "withdraw" => backend.withdraw(request),
        "hold" => backend.hold(request),
        "retire" => {
            ensure!(
                platform.is_some(),
                "rollout retirement lacks boot-storage evidence"
            );
            backend.retire(request, system_now_millis())
        }
        _ => anyhow::bail!("unsupported image-rollout method"),
    }?;
    complete_or_indeterminate(invocation, method, &state)
}

fn reconcile(
    invocation: &Invocation,
    request: &ImageRolloutRequest,
    method: &str,
    provider: &ProviderContext,
    control: &dyn RuntimeControl,
) -> Result<InvocationResult> {
    if control.attempt_remaining_millis() == 0 || control.recovery_remaining_millis() == 0 {
        return result(
            invocation,
            absent_observation(request)?,
            InvocationDisposition::StillIndeterminate,
            BTreeMap::new(),
        );
    }
    let backend = backend();
    let state = if method == "observe-health" {
        observe_health(&backend, request, &provider.health_command, control)?
    } else {
        backend.observe_operation(request, method)?
    };
    complete_or_indeterminate(invocation, method, &state)
}

fn cancel(
    invocation: &Invocation,
    request: &ImageRolloutRequest,
    method: &str,
    _control: &dyn RuntimeControl,
) -> Result<InvocationResult> {
    match backend().observe_operation(request, method) {
        Ok(state) if completion_ready(method, &state) => completed(invocation, method, &state),
        Ok(state) => result(
            invocation,
            observation(&state)?,
            InvocationDisposition::Indeterminate,
            BTreeMap::new(),
        ),
        Err(_) => result(
            invocation,
            absent_observation(request)?,
            InvocationDisposition::RejectedBeforeEffect,
            BTreeMap::new(),
        ),
    }
}

fn complete_or_indeterminate(
    invocation: &Invocation,
    method: &str,
    state: &AbilityRolloutState,
) -> Result<InvocationResult> {
    if completion_ready(method, state) {
        completed(invocation, method, state)
    } else {
        result(
            invocation,
            observation(state)?,
            InvocationDisposition::Indeterminate,
            BTreeMap::new(),
        )
    }
}

fn completed(
    invocation: &Invocation,
    method: &str,
    state: &AbilityRolloutState,
) -> Result<InvocationResult> {
    let evidence = observation(state)?;
    let mut outputs = BTreeMap::from([(LocalKey::new("rollout-state")?, evidence.clone())]);
    if method == "observe-health"
        && let Some(healthy) = observed_health(state)
    {
        outputs.insert(
            LocalKey::new("healthy")?,
            ability_value(serde_json::Value::Bool(healthy))?,
        );
    }
    result(
        invocation,
        evidence,
        InvocationDisposition::Completed,
        outputs,
    )
}

fn result(
    invocation: &Invocation,
    evidence: AbilityValue,
    disposition: InvocationDisposition,
    outputs: BTreeMap<LocalKey, AbilityValue>,
) -> Result<InvocationResult> {
    Ok(InvocationResult {
        schema: RESULT_SCHEMA.into(),
        disposition,
        evidence,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

fn completion_ready(method: &str, state: &AbilityRolloutState) -> bool {
    match method {
        "select" | "observe-boot" => matches!(
            state.phase,
            AbilityRolloutPhase::CandidateBooted
                | AbilityRolloutPhase::HealthyRetained
                | AbilityRolloutPhase::FallbackRetained
        ),
        "observe-health" => state.outcome.is_some(),
        "hold" => matches!(
            state.phase,
            AbilityRolloutPhase::HealthyRetained | AbilityRolloutPhase::FallbackRetained
        ),
        "withdraw" => state.phase == AbilityRolloutPhase::FallbackRetained,
        "retire" => state.phase == AbilityRolloutPhase::Retired,
        _ => true,
    }
}

fn observation(state: &AbilityRolloutState) -> Result<AbilityValue> {
    let (active_image, healthy) = match state.outcome {
        Some(AbilityRolloutOutcome::CandidateHealthy) => ("candidate", Some(true)),
        Some(AbilityRolloutOutcome::CandidateUnhealthy) => ("candidate", Some(false)),
        Some(AbilityRolloutOutcome::PredecessorFallback) => ("predecessor", Some(false)),
        None if matches!(
            state.phase,
            AbilityRolloutPhase::Retained
                | AbilityRolloutPhase::Prepared
                | AbilityRolloutPhase::Drained
        ) =>
        {
            ("predecessor", None)
        }
        None => ("candidate", None),
    };
    let lease = (state.phase != AbilityRolloutPhase::Retired)
        .then_some(state.request.retention_expires_at_millis);
    ability_value(serde_json::json!({
        "active-image": active_image,
        "candidate-prepared": !matches!(state.phase, AbilityRolloutPhase::Retained),
        "drained": !matches!(state.phase, AbilityRolloutPhase::Retained | AbilityRolloutPhase::Prepared),
        "healthy": healthy,
        "lease-expires-at-millis": lease,
        "phase": phase_name(state.phase),
        "schema": OBSERVATION_SCHEMA,
    }))
}

fn absent_observation(request: &ImageRolloutRequest) -> Result<AbilityValue> {
    ability_value(serde_json::json!({
        "active-image": "predecessor",
        "candidate-prepared": false,
        "drained": false,
        "healthy": null,
        "lease-expires-at-millis": request.retention_expires_at_millis,
        "phase": "retained",
        "schema": OBSERVATION_SCHEMA,
    }))
}

fn observed_health(state: &AbilityRolloutState) -> Option<bool> {
    match state.outcome {
        Some(AbilityRolloutOutcome::CandidateHealthy) => Some(true),
        Some(
            AbilityRolloutOutcome::CandidateUnhealthy | AbilityRolloutOutcome::PredecessorFallback,
        ) => Some(false),
        None => None,
    }
}

fn observe_health(
    backend: &NativeImageRolloutBackend,
    request: &ImageRolloutRequest,
    health_command: &str,
    control: &dyn RuntimeControl,
) -> Result<AbilityRolloutState> {
    if let Some(state) = backend.health_assessment_if_recorded(request)? {
        return Ok(state);
    }
    let healthy = SystemRolloutPlatform::new(health_command).health(control)?;
    backend.record_health(request, healthy)
}

fn validate_method(method: &aos_ability_model::MethodReference) -> Result<()> {
    ensure!(
        matches!(
            method.method.as_str(),
            "retain"
                | "prepare"
                | "drain"
                | "select"
                | "observe-boot"
                | "observe-health"
                | "withdraw"
                | "hold"
                | "retire"
        ),
        "unsupported image-rollout method"
    );
    Ok(())
}

fn decode_value<T: serde::de::DeserializeOwned>(value: &AbilityValue) -> Result<T> {
    serde_json::from_value(value.as_json().clone()).context("decoding image-rollout value")
}

fn ability_value(value: serde_json::Value) -> Result<AbilityValue> {
    AbilityValue::new(value).map_err(anyhow::Error::msg)
}

fn backend() -> NativeImageRolloutBackend {
    NativeImageRolloutBackend::new(IMAGE_PROFILE)
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

const fn phase_name(phase: AbilityRolloutPhase) -> &'static str {
    match phase {
        AbilityRolloutPhase::Retained => "retained",
        AbilityRolloutPhase::Prepared => "prepared",
        AbilityRolloutPhase::Drained => "drained",
        AbilityRolloutPhase::Selected => "selected",
        AbilityRolloutPhase::CandidateBooted => "booted",
        AbilityRolloutPhase::HealthyRetained => "healthy-retained",
        AbilityRolloutPhase::FallbackRetained => "fallback-retained",
        AbilityRolloutPhase::Retiring => "retiring",
        AbilityRolloutPhase::Retired => "retired",
    }
}

struct WireControl<'a>(&'a InvocationControl);

impl RuntimeControl for WireControl<'_> {
    fn is_cancelled(&self) -> bool {
        self.0.cancelled
    }

    fn elapsed_millis(&self) -> u64 {
        0
    }

    fn attempt_remaining_millis(&self) -> u64 {
        self.0.attempt_remaining_millis
    }

    fn recovery_remaining_millis(&self) -> u64 {
        self.0.recovery_remaining_millis
    }
}

struct SystemRolloutPlatform<'a> {
    health_command: &'a str,
}

impl<'a> SystemRolloutPlatform<'a> {
    fn new(health_command: &'a str) -> Self {
        Self { health_command }
    }

    fn health(self, control: &dyn RuntimeControl) -> Result<bool> {
        let status = run_bounded_command(&mut Command::new(self.health_command), control)?;
        match status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => anyhow::bail!("assessing rollout health failed with {status}"),
        }
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "rollout admission uses restart-stable host time outside deterministic planning"
)]
fn system_now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::super::RolloutImageIdentity;

    use super::*;

    fn image(seed: char) -> RolloutImageIdentity {
        RolloutImageIdentity {
            toplevel: format!("/nix/store/{}-system", seed.to_string().repeat(32)),
            boot_artifact_contract: format!(
                "/nix/store/{}-boot-artifact-contract",
                seed.to_string().repeat(32)
            ),
            executor: format!("/nix/store/{}-executor", seed.to_string().repeat(32)),
            state_format: "7".into(),
        }
    }

    fn request() -> ImageRolloutRequest {
        ImageRolloutRequest {
            predecessor: image('a'),
            candidate: image('b'),
            retention_expires_at_millis: 2_000,
        }
    }

    fn state(phase: AbilityRolloutPhase) -> AbilityRolloutState {
        AbilityRolloutState {
            schema: "aos.ability.native-image-rollout-state/v1".into(),
            request: request(),
            predecessor_generation: 1,
            candidate_generation: 2,
            phase,
            outcome: None,
        }
    }

    #[test]
    fn absent_admission_evidence_is_schema_shaped_without_creating_state() {
        let evidence = absent_observation(&request()).expect("absent evidence is bounded");

        assert_eq!(evidence.as_json()["schema"], OBSERVATION_SCHEMA);
        assert_eq!(evidence.as_json()["candidate-prepared"], false);
        assert_eq!(evidence.as_json()["active-image"], "predecessor");
    }

    #[test]
    fn completion_waits_for_boot_and_terminal_health() {
        assert!(!completion_ready(
            "select",
            &state(AbilityRolloutPhase::Selected)
        ));
        assert!(completion_ready(
            "select",
            &state(AbilityRolloutPhase::CandidateBooted)
        ));
        assert!(!completion_ready(
            "observe-health",
            &state(AbilityRolloutPhase::CandidateBooted)
        ));

        let mut healthy = state(AbilityRolloutPhase::HealthyRetained);
        healthy.outcome = Some(AbilityRolloutOutcome::CandidateHealthy);
        assert!(completion_ready("observe-health", &healthy));
        assert_eq!(observed_health(&healthy), Some(true));
    }
}
