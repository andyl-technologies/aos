//! Read-only systemd projections for provider-neutral readiness resources.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use aos_ability_model::{AbilityValue, AccessMode, LocalKey, MethodReference, MethodSemantics};
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, INVOCATION_SCHEMA, Invocation, InvocationDisposition,
    InvocationPurpose, InvocationResult, REQUEST_SCHEMA, RESULT_SCHEMA, SupportedPurposes,
    resource_set_digest, validate_admission_resource, validate_resource_context,
    validate_resource_contexts,
};
use aos_systemd::{PinnedSystemdManager, UnitActiveState};

use crate::model::{PROVIDER_CONTEXT_SCHEMA, ProviderContext};
use crate::{decode_value, provider_context, target_context, value};

const NETWORK_INTERFACE: &str = "aos.network.readiness";
const FILESYSTEM_INTERFACE: &str = "aos.filesystem.readiness";
const NETWORK_OBSERVATION_SCHEMA: &str = "aos.ability.network-readiness-observation/v1";
const FILESYSTEM_OBSERVATION_SCHEMA: &str = "aos.ability.filesystem-readiness-observation/v1";

pub(crate) fn supports(method: &MethodReference) -> bool {
    matches!(
        method.interface.name.as_str(),
        NETWORK_INTERFACE | FILESYSTEM_INTERFACE
    )
}

pub(crate) async fn admit(request: AdmissionRequest) -> Result<AdmissionResult> {
    if request.schema != ADMISSION_REQUEST_SCHEMA {
        bail!("unsupported admission request schema");
    }
    validate_admission_resource(&request)?;
    require_method(&request.method, &request.semantics)?;
    if !request.resource_spec.realization.as_json().is_null() {
        bail!("readiness publication unexpectedly carries a desired realization");
    }
    validate_resource_contexts(&request.resources)?;

    let selected = selected_target(&request.method, &request.resource_spec.value)?;
    let manager = PinnedSystemdManager::connect().await?;
    let inspection = inspect(
        &manager,
        &request.method,
        &request.resource_spec.value,
        selected,
    )
    .await?;
    let context = provider_context(&manager, inspection.unit_identity.clone(), false)?;
    let supported_purposes = SupportedPurposes::from_ordered(vec![
        InvocationPurpose::Effect,
        InvocationPurpose::Reconcile,
    ])
    .ok_or_else(|| anyhow::anyhow!("provider purpose set is not canonical"))?;

    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.to_string(),
        disposition: AdmissionDisposition::Admitted,
        revision: AdmissionRevision::Present {
            revision: request.resource_spec.revision,
        },
        incarnation: Some(request.assignment.incarnation),
        observation: inspection.observation,
        native_context: context,
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
    if invocation.method.interface != invocation.request.method.interface {
        bail!("readiness recovery cannot cross interfaces");
    }
    if !matches!(
        invocation.purpose,
        InvocationPurpose::Effect | InvocationPurpose::Reconcile
    ) {
        bail!("readiness provider does not advertise this invocation purpose");
    }
    if resource_set_digest(&invocation.request.resources)?
        != invocation.request.native_context_digest
    {
        bail!("invocation resource-set digest does not match");
    }
    validate_resource_contexts(&invocation.request.resources)?;

    let target = target_context(&invocation)?;
    let bound = validate_resource_context(target)?;
    if invocation.request.inputs != bound.resource_spec.value {
        bail!("invocation inputs differ from the checked readiness request");
    }
    if !bound.resource_spec.realization.as_json().is_null() {
        bail!("readiness publication unexpectedly carries a desired realization");
    }
    let provider: ProviderContext = decode_value(&bound.provider_context)?;
    if provider.schema != PROVIDER_CONTEXT_SCHEMA {
        bail!("unsupported provider context schema");
    }

    let selected = selected_target(&invocation.method, &bound.resource_spec.value)?;
    let manager = PinnedSystemdManager::connect().await?;
    if manager.incarnation().bus_id() != provider.manager_bus_id
        || manager.incarnation().owner() != provider.manager_owner
    {
        bail!("systemd manager changed after admission");
    }
    let inspection = inspect(
        &manager,
        &invocation.method,
        &bound.resource_spec.value,
        selected,
    )
    .await?;
    let mut outputs = BTreeMap::new();
    outputs.insert(
        LocalKey::new("observation")?,
        inspection.observation.clone(),
    );

    Ok(InvocationResult {
        schema: RESULT_SCHEMA.to_string(),
        disposition: InvocationDisposition::Completed,
        evidence: inspection.observation,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

struct Inspection {
    observation: AbilityValue,
    unit_identity: Option<String>,
}

async fn inspect(
    manager: &PinnedSystemdManager,
    method: &MethodReference,
    expected: &AbilityValue,
    unit_name: &str,
) -> Result<Inspection> {
    let unit_identity = match manager.unit_identity(unit_name).await {
        Ok(identity) => Some(identity),
        Err(error) if error.is_no_such_unit() => None,
        Err(error) => return Err(error.into()),
    };
    let active_state = if let Some(identity) = &unit_identity {
        Some(manager.active_state_exact(unit_name, identity).await?)
    } else {
        None
    };
    let state = match active_state {
        Some(UnitActiveState::Active | UnitActiveState::Reloading) => "ready",
        Some(UnitActiveState::Failed) => "failed",
        Some(UnitActiveState::Inactive) => "configuring",
        Some(_) | None => "unknown",
    };
    let schema = if method.interface.name.as_str() == NETWORK_INTERFACE {
        NETWORK_OBSERVATION_SCHEMA
    } else {
        FILESYSTEM_OBSERVATION_SCHEMA
    };
    let observation = value(&serde_json::json!({
        "schema": schema,
        "expected": expected.as_json(),
        "state": state,
    }))?;

    Ok(Inspection {
        observation,
        unit_identity,
    })
}

fn require_method(method: &MethodReference, semantics: &MethodSemantics) -> Result<()> {
    if !supports(method) || method.method.as_str() != "observe" {
        bail!("handler invocation selects an unsupported readiness method");
    }
    if *semantics != MethodSemantics::ordinary(AccessMode::Read) {
        bail!("readiness method carries mismatched semantics");
    }
    Ok(())
}

fn selected_target<'a>(method: &MethodReference, expected: &'a AbilityValue) -> Result<&'a str> {
    match method.interface.name.as_str() {
        NETWORK_INTERFACE => match expected
            .as_json()
            .get("scope")
            .and_then(serde_json::Value::as_str)
        {
            Some("stack-prepared") => Ok("network-pre.target"),
            Some("configured-connectivity" | "default-route" | "local-connectivity") => {
                Ok("network-online.target")
            }
            _ => bail!("network readiness request has an unsupported scope"),
        },
        FILESYSTEM_INTERFACE => match expected
            .as_json()
            .get("scope")
            .and_then(serde_json::Value::as_str)
        {
            Some("local-filesystems") => Ok("local-fs.target"),
            _ => bail!("filesystem readiness request has an unsupported scope"),
        },
        _ => bail!("handler invocation selects an unsupported readiness interface"),
    }
}

#[cfg(test)]
mod tests {
    use aos_ability_model::{AbilityValue, LocalKey, MethodReference};

    use super::{FILESYSTEM_INTERFACE, NETWORK_INTERFACE, selected_target};

    fn method(interface: &str) -> MethodReference {
        serde_json::from_value(serde_json::json!({
            "interface": {
                "name": interface,
                "abi": 1,
                "descriptor": format!("sha256:{}", "1".repeat(64)),
            },
            "method": LocalKey::new("observe").expect("method parses"),
        }))
        .expect("method fixture is valid")
    }

    #[test]
    fn readiness_scopes_map_only_to_package_owned_manager_targets() {
        let online = AbilityValue::new(serde_json::json!({
            "scope": "configured-connectivity",
            "address_families": ["ipv4"],
        }))
        .expect("request is bounded");
        let prepared = AbilityValue::new(serde_json::json!({
            "scope": "stack-prepared",
            "address_families": ["ipv4"],
        }))
        .expect("request is bounded");
        let filesystems = AbilityValue::new(serde_json::json!({
            "scope": "local-filesystems",
        }))
        .expect("request is bounded");

        assert_eq!(
            selected_target(&method(NETWORK_INTERFACE), &online).expect("online target"),
            "network-online.target"
        );
        assert_eq!(
            selected_target(&method(NETWORK_INTERFACE), &prepared).expect("prepared target"),
            "network-pre.target"
        );
        assert_eq!(
            selected_target(&method(FILESYSTEM_INTERFACE), &filesystems)
                .expect("filesystem target"),
            "local-fs.target"
        );
    }
}
