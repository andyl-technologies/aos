//! Native image rollout handler with durable observations of every unsafe phase.
//!
//! This OS handler owns drain, physical boot selection, health, and fallback.
//! Its aggregate operation stays pending across reboot. Started drain and reboot
//! receipts prevent recovery from blindly repeating an uncertain host action.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::path::{Component, Path};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_runtime::activation::{Action, Invocation};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::ability::{AbilityRolloutOutcome, AbilityRolloutPhase, PhysicalRolloutObservation};
use super::{ImageRolloutRequest, NativeImageRolloutBackend};
use crate::sysroot::write_atomic_durable;

const IMAGE_PROFILE: &str = "/var/lib/profiles/image";
const RECEIPT_SCHEMA: &str = "aos.native-image-rollout-receipt/v1";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Executable {
    path: String,
    arguments: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Input {
    rollout: ImageRolloutRequest,
    #[serde(default)]
    retirement: bool,
    platform_executable: String,
    #[serde(default = "default_true")]
    qualified: bool,
    #[serde(default = "default_true")]
    restart: bool,
    #[serde(default)]
    drain: Option<Executable>,
    #[serde(default)]
    drain_observation: Option<Executable>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    effect: String,
    revision: String,
    input_sha256: Sha256Digest,
    input: Input,
    phases: BTreeMap<String, bool>,
}

/// Runs one bounded native apply, remove, or observe invocation.
///
/// # Errors
/// Returns an error for invalid inputs, conflicting retained receipts, uncertain
/// drain/reboot outcomes, incompatible images, or failed physical mutations.
pub fn run_from_process() -> Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    ensure!(arguments.len() == 1, "expected apply, remove, or observe");
    let mut bytes = Vec::new();
    io::stdin().take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "rollout invocation exceeds its bound"
    );
    let invocation: Invocation = serde_json::from_slice(&bytes)?;
    let input: Input = serde_json::from_value(invocation.input.clone())?;
    validate_operation(&input, &invocation.effect.identity)?;
    validate(&input)?;
    let backend = NativeImageRolloutBackend::new(IMAGE_PROFILE);
    let output = match arguments[0].as_str() {
        "apply" if input.retirement => retire(&backend, &input)?,
        "apply" => apply(&backend, &input, &invocation)?,
        "remove" if input.retirement => json!({}),
        "remove" => {
            backend.preflight_operation(&input.rollout, "retire", now_millis()?)?;
            platform(&input, "release", None)?;
            backend.retire(&input.rollout, now_millis()?)?;
            json!({})
        }
        "observe" if input.retirement && matches!(invocation.action, Action::Remove) => {
            json!({"status":"absent"})
        }
        "observe" if input.retirement => {
            match backend.observe_operation(&input.rollout, "retire") {
                Ok(_)
                    if platform(&input, "observe-release", None)?
                        .get("retired")
                        .and_then(Value::as_bool)
                        == Some(true) =>
                {
                    json!({"status":"current","outputs":retirement_output(&backend,&input)?})
                }
                Ok(_) => json!({"status":"indeterminate"}),
                Err(_) => json!({"status":"retry-safe"}),
            }
        }
        "observe" if matches!(invocation.action, Action::Remove) => {
            match backend.observe_operation(&input.rollout, "retire") {
                Ok(_) => {
                    if platform(&input, "observe-release", None)?
                        .get("retired")
                        .and_then(Value::as_bool)
                        == Some(true)
                    {
                        json!({"status":"absent"})
                    } else {
                        json!({"status":"indeterminate"})
                    }
                }
                Err(_) => {
                    let storage = platform(&input, "observe-storage", None)?;
                    let retained = storage.get("state").and_then(Value::as_str) == Some("retained");
                    let released = if retained {
                        false
                    } else {
                        platform(&input, "observe-release", None)?
                            .get("retired")
                            .and_then(Value::as_bool)
                            == Some(true)
                    };
                    if retained || released {
                        json!({"status":"retry-safe"})
                    } else {
                        json!({"status":"indeterminate"})
                    }
                }
            }
        }
        "observe" => observe(&backend, &input, &invocation)?,
        _ => bail!("expected apply, remove, or observe"),
    };
    io::stdout().write_all(&serde_json::to_vec(&output)?)?;
    Ok(())
}

fn default_true() -> bool {
    true
}

fn validate_operation(input: &Input, identity: &[String]) -> Result<()> {
    ensure!(
        identity.len() >= 4 && identity[identity.len() - 2] == "ensure",
        "image handler has an invalid admitted operation identity"
    );
    let intent_matches = match identity[identity.len() - 3].as_str() {
        "imageRollout" => input.qualified && !input.retirement,
        "imageSelection" => !input.qualified && !input.retirement,
        "imageRetirement" => input.retirement,
        _ => false,
    };
    ensure!(
        intent_matches,
        "image intent differs from its admitted operation contract"
    );
    Ok(())
}

fn validate(input: &Input) -> Result<()> {
    ensure!(
        input.retirement
            || !input.qualified
            || (input.drain.is_some() && input.drain_observation.is_some()),
        "qualified rollout requires explicit drain and observation programs"
    );
    ensure!(
        input.retirement
            || input.qualified
            || input.rollout.predecessor.executor == input.rollout.candidate.executor,
        "executor replacement requires qualified rollout"
    );
    immutable_executable(&input.platform_executable)?;
    for executable in [&input.drain, &input.drain_observation]
        .into_iter()
        .flatten()
    {
        immutable_executable(&executable.path)?;
        ensure!(
            executable.arguments.len() <= 256
                && executable
                    .arguments
                    .iter()
                    .all(|argument| argument.len() <= 16 * 1024 && !argument.contains('\0')),
            "drain arguments exceed their bound"
        );
    }
    ensure!(
        !input.rollout.candidate.state_format.is_empty()
            && input.rollout.candidate.state_format == input.rollout.predecessor.state_format,
        "rollout state formats are incompatible"
    );
    Ok(())
}

fn immutable_executable(path: &str) -> Result<()> {
    let path = Path::new(path);
    ensure!(
        path.is_absolute()
            && path.starts_with("/nix/store")
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
            && path.strip_prefix("/nix/store")?.components().count() > 1,
        "rollout executable is not an immutable normalized file"
    );
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file(),
        "rollout executable is not a regular file"
    );
    ensure!(
        fs::canonicalize(path)? == path,
        "rollout executable is not canonical"
    );
    Ok(())
}

fn load_receipt(
    backend: &NativeImageRolloutBackend,
    input: &Input,
    invocation: &Invocation,
) -> Result<Option<Receipt>> {
    let path = backend
        .execution_directory(&input.rollout)?
        .join("native-receipt.json");
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        bytes.len() <= 64 * 1024,
        "rollout receipt exceeds its bound"
    );
    let receipt: Receipt = serde_json::from_slice(&bytes)?;
    ensure!(
        receipt.schema == RECEIPT_SCHEMA
            && receipt.effect == invocation.id
            && receipt.revision == invocation.revision
            && receipt.input_sha256 == Sha256Digest::of_bytes(&serde_json::to_vec(input)?),
        "rollout receipt differs from native effect identity"
    );
    Ok(Some(receipt))
}

fn save_receipt(
    backend: &NativeImageRolloutBackend,
    input: &Input,
    receipt: &Receipt,
) -> Result<()> {
    let path = backend
        .execution_directory(&input.rollout)?
        .join("native-receipt.json");
    let bytes = serde_json::to_vec(receipt)?;
    write_atomic_durable(&path, &bytes)?;
    write_atomic_durable(
        &Path::new(IMAGE_PROFILE).join("active-native-rollout.json"),
        &bytes,
    )
}

fn complete(
    backend: &NativeImageRolloutBackend,
    input: &Input,
    receipt: &mut Receipt,
    phase: &str,
) -> Result<()> {
    receipt.phases.insert(phase.into(), true);
    save_receipt(backend, input, receipt)
}

fn retirement_output(backend: &NativeImageRolloutBackend, input: &Input) -> Result<Value> {
    Ok(json!({"rollout":input.rollout,"outcome":"retired",
        "retentionDirectory":backend.execution_directory(&input.rollout)?}))
}

fn retire(backend: &NativeImageRolloutBackend, input: &Input) -> Result<Value> {
    if backend.observe_operation(&input.rollout, "retire").is_err() {
        backend.preflight_operation(&input.rollout, "retire", now_millis()?)?;
        platform(input, "release", None)?;
        backend.retire(&input.rollout, now_millis()?)?;
    }
    ensure!(
        platform(input, "observe-storage", None)?
            .get("state")
            .and_then(Value::as_str)
            == Some("absent"),
        "physical retention remains after retirement"
    );
    retirement_output(backend, input)
}

fn apply(
    backend: &NativeImageRolloutBackend,
    input: &Input,
    invocation: &Invocation,
) -> Result<Value> {
    platform(
        input,
        if input.qualified {
            "validate"
        } else {
            "validate-selection"
        },
        None,
    )?;
    backend.preflight_operation(&input.rollout, "retain", now_millis()?)?;
    let mut receipt = match load_receipt(backend, input, invocation)? {
        Some(receipt) => receipt,
        None => {
            // Retention is idempotent and precedes every host-side mutation.
            platform(input, "retain", None)?;
            backend.retain(&input.rollout)?;
            let receipt = Receipt {
                schema: RECEIPT_SCHEMA.into(),
                effect: invocation.id.clone(),
                revision: invocation.revision.clone(),
                input_sha256: Sha256Digest::of_bytes(&serde_json::to_vec(input)?),
                input: input.clone(),
                phases: BTreeMap::new(),
            };
            save_receipt(backend, input, &receipt)?;
            receipt
        }
    };
    let mut state = backend.observe_operation(&input.rollout, "retain")?;
    if state.phase == AbilityRolloutPhase::Retained {
        state = backend.prepare(&input.rollout)?;
    }
    if !input.qualified {
        if state.phase == AbilityRolloutPhase::Prepared {
            backend.select_unqualified(&input.rollout)?;
        }
        ensure_selection(input)?;
        complete(backend, input, &mut receipt, "selection")?;
        if input.restart {
            request_restart(backend, input, &mut receipt, "candidate-restart")?;
        }
        return selected_output(backend, input);
    }
    let drain = input
        .drain
        .as_ref()
        .context("qualified drain program is absent")?;
    let drain_observation = input
        .drain_observation
        .as_ref()
        .context("qualified drain observation is absent")?;
    if state.phase == AbilityRolloutPhase::Prepared {
        match receipt.phases.get("drain") {
            Some(true) => {}
            Some(false) => ensure!(
                run_drain_observation(drain_observation)?,
                "interrupted drain has no completed observation"
            ),
            None => {
                receipt.phases.insert("drain".into(), false);
                save_receipt(backend, input, &receipt)?;
                let status = Command::new(&drain.path)
                    .env_clear()
                    .args(&drain.arguments)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .status()?;
                ensure!(
                    status.success(),
                    "configured workload drain failed: {status}"
                );
            }
        }
        complete(backend, input, &mut receipt, "drain")?;
        state = backend.drain(&input.rollout)?;
    }
    if state.phase == AbilityRolloutPhase::Drained {
        let resolved = platform(input, "resolve", None)?;
        let entry = resolved
            .get("entry")
            .and_then(Value::as_str)
            .context("platform omitted resolved boot entry")?;
        backend.select(&input.rollout, entry)?;
        // Native authority is durable before the idempotent physical selection.
        platform(input, "select", Some(entry))?;
        complete(backend, input, &mut receipt, "selection")?;
    }
    if state.phase == AbilityRolloutPhase::Selected && boot_counter_exhausted(input)? {
        backend.record_boot_failure(&input.rollout)?;
        platform(input, "select-fallback", None)?;
    }
    match backend.observe(&input.rollout)? {
        PhysicalRolloutObservation::AwaitingBoot => {
            ensure_selection(input)?;
            request_restart(backend, input, &mut receipt, "candidate-restart")?;
            bail!("rollout awaits authenticated candidate boot");
        }
        PhysicalRolloutObservation::CandidateBooted => {
            backend.reconcile(&input.rollout)?;
            let assessed = match backend.health_assessment_if_recorded(&input.rollout)? {
                Some(state) => state,
                None => {
                    let health = platform(input, "health", None)?;
                    let healthy = health
                        .get("healthy")
                        .and_then(Value::as_bool)
                        .context("platform omitted typed health outcome")?;
                    backend.record_health(&input.rollout, healthy)?
                }
            };
            if assessed.outcome == Some(AbilityRolloutOutcome::CandidateUnhealthy) {
                backend.withdraw(&input.rollout)?;
                platform(input, "select-fallback", None)?;
                request_restart(backend, input, &mut receipt, "fallback-restart")?;
                bail!("rollout awaits authenticated predecessor fallback");
            }
            backend.hold(&input.rollout)?;
        }
        PhysicalRolloutObservation::FallbackPendingCommit
        | PhysicalRolloutObservation::Fallback => {
            backend.reconcile(&input.rollout)?;
            backend.withdraw(&input.rollout)?;
            backend.hold(&input.rollout)?;
        }
        PhysicalRolloutObservation::Healthy => {
            backend.hold(&input.rollout)?;
        }
    }
    platform(input, "mark", None)?;
    complete(backend, input, &mut receipt, "success")?;
    output(backend, input)
}

fn boot_counter_exhausted(input: &Input) -> Result<bool> {
    let observation = platform(input, "observe-boot-failure", None)?;
    observation
        .get("exhausted")
        .and_then(Value::as_bool)
        .context("platform omitted typed pre-boot failure observation")
}

fn ensure_selection(input: &Input) -> Result<()> {
    let resolved = platform(input, "resolve", None)?;
    let entry = resolved
        .get("entry")
        .and_then(Value::as_str)
        .context("platform omitted resolved boot entry")?;
    let selected = platform(input, "observe-selection", Some(entry))?;
    if selected.get("state").and_then(Value::as_str) != Some("selected") {
        platform(input, "select", Some(entry))?;
    }
    Ok(())
}

fn request_restart(
    backend: &NativeImageRolloutBackend,
    input: &Input,
    receipt: &mut Receipt,
    phase: &str,
) -> Result<()> {
    if receipt.phases.contains_key(phase) {
        // Both accepted and uncertain requests require physical boot evidence.
        // Repeated restart commands could interrupt recovery or fallback.
        return Ok(());
    }
    receipt.phases.insert(phase.into(), false);
    save_receipt(backend, input, receipt)?;
    platform(input, "restart", None)?;
    complete(backend, input, receipt, phase)
}

fn run_drain_observation(executable: &Executable) -> Result<bool> {
    let status = Command::new(&executable.path)
        .env_clear()
        .args(&executable.arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => bail!("drain observation returned an indeterminate status"),
    }
}

fn selected_output(backend: &NativeImageRolloutBackend, input: &Input) -> Result<Value> {
    Ok(json!({"rollout":input.rollout,"outcome":"selected",
        "retentionDirectory":backend.execution_directory(&input.rollout)?}))
}

fn output(backend: &NativeImageRolloutBackend, input: &Input) -> Result<Value> {
    let state = backend.observe_operation(&input.rollout, "hold")?;
    let outcome = match state.outcome {
        Some(AbilityRolloutOutcome::CandidateHealthy) => "candidate-healthy",
        Some(AbilityRolloutOutcome::PredecessorFallback) => "predecessor-fallback",
        _ => bail!("rollout has no retained terminal outcome"),
    };
    Ok(json!({"rollout":input.rollout,"outcome":outcome,
        "retentionDirectory":backend.execution_directory(&input.rollout)?}))
}

fn observe(
    backend: &NativeImageRolloutBackend,
    input: &Input,
    invocation: &Invocation,
) -> Result<Value> {
    observe_with_transport(backend, input, invocation, platform)
}

fn observe_with_transport(
    backend: &NativeImageRolloutBackend,
    input: &Input,
    invocation: &Invocation,
    mut transport: impl FnMut(&Input, &str, Option<&str>) -> Result<Value>,
) -> Result<Value> {
    let Some(receipt) = load_receipt(backend, input, invocation)? else {
        return Ok(json!({"status":"retry-safe"}));
    };
    if receipt.phases.get("selection") == Some(&true)
        || receipt.phases.get("success") == Some(&true)
    {
        // Firmware preference or a success marker cannot authenticate the
        // payload lease. Lost-result recovery requires its actual retained
        // bytes before returning the original invocation's outputs.
        let storage = transport(input, "observe-storage", None)?;
        if storage.get("state").and_then(Value::as_str) != Some("retained") {
            return Ok(json!({"status":"indeterminate"}));
        }
    }
    if !input.qualified && receipt.phases.get("selection") == Some(&true) {
        let resolved = transport(input, "resolve", None)?;
        let entry = resolved
            .get("entry")
            .and_then(Value::as_str)
            .context("missing resolved entry")?;
        let observed = transport(input, "observe-selection", Some(entry))?;
        if observed.get("state").and_then(Value::as_str) == Some("selected") {
            return Ok(json!({"status":"current","outputs":selected_output(backend,input)?}));
        }
    }
    if receipt.phases.get("success") == Some(&true) {
        let marked = transport(input, "observe-success", None)?;
        if marked.get("state").and_then(Value::as_str) == Some("marked") {
            return Ok(json!({"status":"current","outputs":output(backend,input)?}));
        }
    }
    let state = backend.observe_operation(&input.rollout, "retain")?;
    if state.phase == AbilityRolloutPhase::Prepared
        && receipt.phases.get("drain") == Some(&false)
        && !run_drain_observation(
            input
                .drain_observation
                .as_ref()
                .context("missing drain observation")?,
        )?
    {
        return Ok(json!({"status":"indeterminate"}));
    }
    if state.phase == AbilityRolloutPhase::Selected
        && receipt.phases.contains_key("candidate-restart")
        && boot_counter_exhausted(input)?
    {
        // The pending apply must publish the distinct failure branch; observing
        // the physical witness alone never manufactures a finished receipt.
        return Ok(json!({"status":"retry-safe"}));
    }
    if matches!(
        state.phase,
        AbilityRolloutPhase::Selected | AbilityRolloutPhase::CandidateBooted
    ) && backend.observe(&input.rollout)? == PhysicalRolloutObservation::AwaitingBoot
        && receipt.phases.contains_key("candidate-restart")
        && !boot_counter_exhausted(input)?
    {
        return Ok(json!({"status":"indeterminate"}));
    }
    Ok(json!({"status":"retry-safe"}))
}

fn platform(input: &Input, operation: &str, entry: Option<&str>) -> Result<Value> {
    let mut child = Command::new(&input.platform_executable)
        .env_clear()
        .arg(operation)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    serde_json::to_writer(
        child.stdin.take().context("platform stdin is absent")?,
        &json!({"rollout":input.rollout,"entry":entry}),
    )?;
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .context("platform stdout is absent")?
        .take(64 * 1024 + 1)
        .read_to_end(&mut output)?;
    let status = child.wait()?;
    ensure!(
        status.success() && output.len() <= 64 * 1024,
        "boot platform operation failed or exceeded its output bound"
    );
    serde_json::from_slice(&output).context("decoding boot platform operation result")
}

fn now_millis() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

#[cfg(test)]
mod tests {
    use super::super::RolloutImageIdentity;
    use super::*;

    fn input() -> Input {
        let identity = RolloutImageIdentity {
            toplevel: "/nix/store/image".into(),
            boot_artifact_contract: "/nix/store/contract".into(),
            executor: "/nix/store/executor".into(),
            state_format: "7".into(),
        };
        Input {
            rollout: ImageRolloutRequest {
                predecessor: identity.clone(),
                candidate: identity,
                retention_expires_at_millis: 2_000,
            },
            platform_executable: "/invalid-platform".into(),
            retirement: false,
            qualified: true,
            restart: true,
            drain: None,
            drain_observation: None,
        }
    }

    #[test]
    fn retirement_contract_cannot_dispatch_selection() {
        let mut input = input();
        let identity = vec![
            "profile".into(),
            "system".into(),
            "aos".into(),
            "imageRetirement".into(),
            "ensure".into(),
            "lease".into(),
        ];
        assert!(validate_operation(&input, &identity).is_err());
        input.retirement = true;
        validate_operation(&input, &identity).unwrap();
        let selection = vec![
            "profile".into(),
            "system".into(),
            "aos".into(),
            "imageSelection".into(),
            "ensure".into(),
            "selected".into(),
        ];
        assert!(validate_operation(&input, &selection).is_err());
    }

    #[test]
    fn absent_drain_is_rejected_before_any_platform_invocation() {
        let error = validate(&input()).unwrap_err();
        assert!(error.to_string().contains("explicit drain and observation"));
    }

    #[test]
    fn uncertain_and_accepted_restarts_are_never_reissued() {
        let directory = tempfile::tempdir().unwrap();
        let backend = NativeImageRolloutBackend::new(directory.path());
        let input = input();
        for completed in [false, true] {
            let mut receipt = Receipt {
                schema: RECEIPT_SCHEMA.into(),
                effect: "effect".into(),
                revision: "revision".into(),
                input_sha256: Sha256Digest::of_bytes(b"input"),
                input: input.clone(),
                phases: BTreeMap::from([("candidate-restart".into(), completed)]),
            };
            request_restart(&backend, &input, &mut receipt, "candidate-restart").unwrap();
            assert_eq!(receipt.phases.get("candidate-restart"), Some(&completed));
            assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
        }
    }

    #[test]
    fn lost_results_require_retained_payloads_before_selection_or_success_proofs() {
        let directory = tempfile::tempdir().unwrap();
        let backend = NativeImageRolloutBackend::new(directory.path());
        let input = input();
        let effect = serde_json::from_value(json!({
            "owner": "aos", "identity": ["test", "aos", "imageRollout", "ensure", "qualified"],
            "input": {}, "inputs": {},
            "input_type": {"kind":"submodule", "open":false, "fields":{}},
            "after": [], "results": {},
            "handler": {"kind":"process", "artifact":"/nix/store/fixture", "executable":"/nix/store/fixture/bin/handler"},
            "dependencies": [], "revision":"revision", "lifetime":"persistent", "timeout_ms":1000
        })).unwrap();
        let invocation = Invocation {
            id: "effect".into(),
            effect,
            input: serde_json::to_value(&input).unwrap(),
            revision: "revision".into(),
            action: Action::Apply,
            previous: None,
        };
        let execution = backend.execution_directory(&input.rollout).unwrap();
        fs::create_dir_all(&execution).unwrap();

        for phase in ["selection", "success"] {
            let receipt = Receipt {
                schema: RECEIPT_SCHEMA.into(),
                effect: invocation.id.clone(),
                revision: invocation.revision.clone(),
                input_sha256: Sha256Digest::of_bytes(serde_json::to_vec(&input).unwrap()),
                input: input.clone(),
                phases: BTreeMap::from([(phase.into(), true)]),
            };
            fs::write(
                execution.join("native-receipt.json"),
                serde_json::to_vec(&receipt).unwrap(),
            )
            .unwrap();
            let mut calls = Vec::new();
            let result =
                observe_with_transport(&backend, &input, &invocation, |_, operation, _| {
                    calls.push(operation.to_owned());
                    Ok(json!({"state":"absent"}))
                })
                .unwrap();

            assert_eq!(result, json!({"status":"indeterminate"}));
            assert_eq!(calls, ["observe-storage"]);
        }
    }
}
