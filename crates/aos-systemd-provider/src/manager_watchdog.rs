//! Reconciliation of package-owned systemd manager watchdog configuration.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use aos_ability_model::{AccessMode, LocalKey, MethodReference, MethodSemantics, RevisionId};
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, INVOCATION_SCHEMA, Invocation, InvocationDisposition,
    InvocationPurpose, InvocationResult, REQUEST_SCHEMA, RESULT_SCHEMA, SupportedPurposes,
    resource_set_digest, validate_admission_resource, validate_resource_context,
    validate_resource_contexts,
};
use aos_systemd::PinnedSystemdManager;

use crate::materialize::{
    ensure_directory, publish_file, remove_managed_path, verify_file_exact_or_absent,
};
use crate::model::{
    MANAGER_WATCHDOG_CONTEXT_SCHEMA, MANAGER_WATCHDOG_REALIZATION_SCHEMA, ManagerWatchdogContext,
    ManagerWatchdogEffectsRequest, ManagerWatchdogObservation, ManagerWatchdogRealization,
    ManagerWatchdogRequest, ManagerWatchdogState,
};
use crate::{decode_value, target_context, value};

const CONFIGURATION_PATH: &str = "systemd/system.conf.d/50-aos-watchdog.conf";
const RECEIPT_ROOT: &str = "aos/ability-revisions/systemd-manager-watchdog/sha256";
const RECONNECT_LIMIT: Duration = Duration::from_secs(10);
const RECONNECT_DELAY: Duration = Duration::from_millis(100);

pub(crate) fn render(realization: &ManagerWatchdogRealization) -> Result<Vec<u8>> {
    if realization.schema != MANAGER_WATCHDOG_REALIZATION_SCHEMA {
        bail!("unsupported manager-watchdog realization schema");
    }

    let runtime = configured_timeout(realization.enabled, realization.runtime_timeout_millis);
    let reboot = configured_timeout(realization.enabled, realization.reboot_timeout_millis);
    let kexec = configured_timeout(realization.enabled, realization.kexec_timeout_millis);
    Ok(format!(
        "[Manager]\nRuntimeWatchdogSec={runtime}\nRebootWatchdogSec={reboot}\nKExecWatchdogSec={kexec}\n"
    )
    .into_bytes())
}

pub(crate) async fn admit(request: AdmissionRequest) -> Result<AdmissionResult> {
    if request.schema != ADMISSION_REQUEST_SCHEMA {
        bail!("unsupported admission request schema");
    }
    validate_admission_resource(&request)?;
    require_method(&request.method, &request.semantics)?;
    validate_resource_contexts(&request.resources)?;
    let observation_schema = request
        .contract
        .observation_discriminator_at(&["observation", "schema"])
        .context("selected manager-watchdog method has no exact observation discriminator")?;

    let expected: ManagerWatchdogRequest = decode_value(&request.resource_spec.value)?;
    let realization: ManagerWatchdogRealization = decode_value(&request.resource_spec.realization)?;
    require_matching_request(&expected, &realization)?;
    let bytes = render(&realization)?;
    let paths = paths_for(Path::new("/etc"), request.resource_spec.revision);
    let files_match = files_match(&paths, &bytes, request.resource_spec.revision)?;
    let manager = PinnedSystemdManager::connect().await?;
    let observation = observation(observation_schema, &expected, files_match, false)?;
    let supported_purposes = SupportedPurposes::from_ordered(vec![
        InvocationPurpose::Effect,
        InvocationPurpose::Reconcile,
    ])
    .ok_or_else(|| anyhow::anyhow!("provider purpose set is not canonical"))?;

    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.to_string(),
        disposition: AdmissionDisposition::Admitted,
        revision: if files_match {
            AdmissionRevision::Present {
                revision: request.resource_spec.revision,
            }
        } else {
            AdmissionRevision::Absent
        },
        incarnation: Some(request.assignment.incarnation),
        observation: observation.clone(),
        native_context: value(&ManagerWatchdogContext {
            schema: MANAGER_WATCHDOG_CONTEXT_SCHEMA.to_string(),
            manager_bus_id: manager.incarnation().bus_id().to_string(),
            manager_owner: manager.incarnation().owner().to_string(),
            materialization_owned: files_match,
        })?,
        supported_purposes,
    })
}

pub(crate) async fn invoke(invocation: Invocation) -> Result<InvocationResult> {
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
    let observation_schema = invocation
        .contract
        .observation_discriminator_at(&["observation", "schema"])
        .context("selected manager-watchdog method has no exact observation discriminator")?;

    let target = target_context(&invocation)?;
    let bound = validate_resource_context(target)?;
    let expected: ManagerWatchdogRequest = decode_value(&bound.resource_spec.value)?;
    let effect: ManagerWatchdogEffectsRequest = decode_value(&invocation.request.inputs)?;
    if effect.desired() != &expected {
        bail!("manager-watchdog effect inputs differ from the checked desired resource");
    }
    let realization: ManagerWatchdogRealization = decode_value(&bound.resource_spec.realization)?;
    require_matching_request(&expected, &realization)?;
    let provider: ManagerWatchdogContext = decode_value(&bound.provider_context)?;
    if provider.schema != MANAGER_WATCHDOG_CONTEXT_SCHEMA {
        bail!("unsupported manager-watchdog provider context schema");
    }

    let manager = PinnedSystemdManager::connect().await?;
    require_manager(&manager, &provider)?;
    let bytes = render(&realization)?;
    let paths = paths_for(Path::new("/etc"), bound.resource_spec.revision);
    let method = invocation.method.method.as_str();
    let remove = method == "remove";
    let mutate = invocation.purpose == InvocationPurpose::Effect
        || (invocation.purpose == InvocationPurpose::Reconcile
            && matches!(method, "create" | "update" | "remove" | "reconcile"));

    let manager_changed = if mutate {
        if remove {
            remove_exact(&paths, &bytes, bound.resource_spec.revision)?;
        } else {
            materialize(&paths, &bytes, bound.resource_spec.revision)?;
        }
        let previous_bus = manager.incarnation().bus_id().to_string();
        let previous_owner = manager.incarnation().owner().to_string();
        manager.reexecute().await?;
        drop(manager);
        wait_for_reexecution(&previous_bus, &previous_owner).await?;
        true
    } else {
        false
    };

    let matches = if remove {
        files_absent(&paths)?
    } else {
        files_match(&paths, &bytes, bound.resource_spec.revision)?
    };
    let raw_observation = observation_for_goal(
        observation_schema,
        &expected,
        matches,
        remove,
        manager_changed,
    )?;
    let evidence = effect_observation(&raw_observation)?;
    let mut outputs = BTreeMap::new();
    outputs.insert(LocalKey::new("observation")?, evidence.clone());

    Ok(InvocationResult {
        schema: RESULT_SCHEMA.to_string(),
        disposition: InvocationDisposition::Completed,
        evidence,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

fn configured_timeout(enabled: bool, millis: u64) -> String {
    if enabled {
        format!("{millis}ms")
    } else {
        "0".to_string()
    }
}

fn require_matching_request(
    request: &ManagerWatchdogRequest,
    realization: &ManagerWatchdogRealization,
) -> Result<()> {
    if realization.schema != MANAGER_WATCHDOG_REALIZATION_SCHEMA
        || request.enabled != realization.enabled
        || request.runtime_timeout_millis != realization.runtime_timeout_millis
        || request.reboot_timeout_millis != realization.reboot_timeout_millis
        || request.kexec_timeout_millis != realization.kexec_timeout_millis
    {
        bail!("manager-watchdog realization differs from the checked request");
    }
    Ok(())
}

fn require_method(method: &MethodReference, semantics: &MethodSemantics) -> Result<()> {
    let expected = match method.method.as_str() {
        "observe" => MethodSemantics::ordinary(AccessMode::Read),
        "remove" => MethodSemantics::provider_stop(),
        "create" | "reconcile" | "update" => MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
        _ => bail!("handler invocation selects an unsupported manager-watchdog method"),
    };
    if *semantics != expected {
        bail!("manager-watchdog method carries mismatched semantics");
    }
    Ok(())
}

fn require_manager(manager: &PinnedSystemdManager, context: &ManagerWatchdogContext) -> Result<()> {
    if manager.incarnation().bus_id() != context.manager_bus_id
        || manager.incarnation().owner() != context.manager_owner
    {
        bail!("systemd manager changed after manager-watchdog admission");
    }
    Ok(())
}

struct WatchdogPaths {
    configuration: PathBuf,
    receipt: PathBuf,
}

fn paths_for(root: &Path, revision: RevisionId) -> WatchdogPaths {
    WatchdogPaths {
        configuration: root.join(CONFIGURATION_PATH),
        receipt: root.join(RECEIPT_ROOT).join(revision.0.hex()),
    }
}

fn receipt_bytes(revision: RevisionId) -> Result<Vec<u8>> {
    aos_contract::canonical::to_vec(&serde_json::json!({
        "schema": "aos.systemd.manager-watchdog-revision/v1",
        "revision": revision,
    }))
    .context("encoding manager-watchdog revision receipt")
}

fn materialize(paths: &WatchdogPaths, bytes: &[u8], revision: RevisionId) -> Result<()> {
    let configuration_parent = paths
        .configuration
        .parent()
        .ok_or_else(|| anyhow::anyhow!("manager-watchdog configuration has no parent"))?;
    let receipt_parent = paths
        .receipt
        .parent()
        .ok_or_else(|| anyhow::anyhow!("manager-watchdog receipt has no parent"))?;
    ensure_directory(configuration_parent)?;
    ensure_directory(receipt_parent)?;
    publish_file(&paths.configuration, bytes)?;
    publish_file(&paths.receipt, &receipt_bytes(revision)?)
}

fn remove_exact(paths: &WatchdogPaths, bytes: &[u8], revision: RevisionId) -> Result<()> {
    if verify_file_exact_or_absent(&paths.configuration, bytes)? {
        remove_managed_path(&paths.configuration)?;
    }
    if verify_file_exact_or_absent(&paths.receipt, &receipt_bytes(revision)?)? {
        remove_managed_path(&paths.receipt)?;
    }
    Ok(())
}

fn files_match(paths: &WatchdogPaths, bytes: &[u8], revision: RevisionId) -> Result<bool> {
    Ok(verify_file_exact_or_absent(&paths.configuration, bytes)?
        && verify_file_exact_or_absent(&paths.receipt, &receipt_bytes(revision)?)?)
}

fn files_absent(paths: &WatchdogPaths) -> Result<bool> {
    Ok(!paths.configuration.exists() && !paths.receipt.exists())
}

fn observation(
    observation_schema: &str,
    expected: &ManagerWatchdogRequest,
    matches: bool,
    manager_incarnation_changed: bool,
) -> Result<aos_ability_model::AbilityValue> {
    observation_for_goal(
        observation_schema,
        expected,
        matches,
        false,
        manager_incarnation_changed,
    )
}

fn observation_for_goal(
    observation_schema: &str,
    expected: &ManagerWatchdogRequest,
    matches: bool,
    absent_goal: bool,
    manager_incarnation_changed: bool,
) -> Result<aos_ability_model::AbilityValue> {
    let mut discrepancies = Vec::new();
    if !matches {
        discrepancies.push(LocalKey::new("configuration")?);
    }
    let state = if !matches {
        ManagerWatchdogState::Divergent
    } else if absent_goal {
        ManagerWatchdogState::Absent
    } else {
        ManagerWatchdogState::Configured
    };
    value(&ManagerWatchdogObservation {
        schema: observation_schema.to_string(),
        expected: expected.clone(),
        observed: if matches && !absent_goal {
            Some(expected.clone())
        } else {
            None
        },
        state,
        manager_incarnation_changed,
        discrepancies,
    })
}

fn effect_observation(
    observation: &aos_ability_model::AbilityValue,
) -> Result<aos_ability_model::AbilityValue> {
    value(&serde_json::json!({
        "kind": "manager-watchdog",
        "observation": observation.as_json(),
    }))
}

async fn wait_for_reexecution(previous_bus: &str, previous_owner: &str) -> Result<()> {
    let deadline = Instant::now() + RECONNECT_LIMIT;
    loop {
        match PinnedSystemdManager::connect().await {
            Ok(manager)
                if manager.incarnation().bus_id() != previous_bus
                    || manager.incarnation().owner() != previous_owner =>
            {
                return Ok(());
            }
            Ok(_) | Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
            Ok(_) => bail!("systemd manager did not change incarnation after re-execution"),
            Err(error) => return Err(error).context("reconnecting after systemd re-execution"),
        }
    }
}

#[cfg(test)]
mod tests {
    use aos_ability_model::RevisionId;
    use aos_contract::Sha256Digest;
    use tempfile::TempDir;

    use super::{files_absent, files_match, materialize, paths_for, remove_exact, render};
    use crate::model::ManagerWatchdogRealization;

    fn revision() -> RevisionId {
        RevisionId(Sha256Digest::of_bytes(b"watchdog-test"))
    }

    fn realization(enabled: bool) -> ManagerWatchdogRealization {
        ManagerWatchdogRealization {
            schema: "aos.systemd.manager-watchdog-realization/v1".to_string(),
            enabled,
            runtime_timeout_millis: 30_000,
            reboot_timeout_millis: 60_000,
            kexec_timeout_millis: 60_000,
        }
    }

    #[test]
    fn renderer_emits_exact_enabled_and_disabled_configuration() {
        assert_eq!(
            render(&realization(true)).expect("enabled rendering succeeds"),
            b"[Manager]\nRuntimeWatchdogSec=30000ms\nRebootWatchdogSec=60000ms\nKExecWatchdogSec=60000ms\n"
        );
        assert_eq!(
            render(&realization(false)).expect("disabled rendering succeeds"),
            b"[Manager]\nRuntimeWatchdogSec=0\nRebootWatchdogSec=0\nKExecWatchdogSec=0\n"
        );
    }

    #[test]
    fn materialization_and_removal_are_exact_and_idempotent() {
        let root = TempDir::new().expect("temporary directory is created");
        let paths = paths_for(root.path(), revision());
        let bytes = render(&realization(true)).expect("rendering succeeds");

        materialize(&paths, &bytes, revision()).expect("materialization succeeds");
        assert!(files_match(&paths, &bytes, revision()).expect("exact files inspect"));

        remove_exact(&paths, &bytes, revision()).expect("removal succeeds");
        assert!(files_absent(&paths).expect("absence inspects"));
        remove_exact(&paths, &bytes, revision()).expect("repeated removal succeeds");
    }

    #[test]
    fn removal_rejects_divergent_configuration() {
        let root = TempDir::new().expect("temporary directory is created");
        let paths = paths_for(root.path(), revision());
        let bytes = render(&realization(true)).expect("rendering succeeds");
        materialize(&paths, &bytes, revision()).expect("materialization succeeds");
        std::fs::write(&paths.configuration, b"changed").expect("fixture mutates file");

        assert!(remove_exact(&paths, &bytes, revision()).is_err());
    }
}
