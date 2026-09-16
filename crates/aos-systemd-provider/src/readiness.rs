//! Read-only systemd projections for provider-neutral readiness resources.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadinessRole {
    ActivationMilestone,
    Filesystem,
    Network,
    RuntimeEntryPopulation,
    SystemMilestone,
}

impl ReadinessRole {
    fn inactive_state(self) -> &'static str {
        match self {
            Self::ActivationMilestone | Self::RuntimeEntryPopulation | Self::SystemMilestone => {
                "pending"
            }
            Self::Filesystem | Self::Network => "configuring",
        }
    }
}

pub(crate) async fn admit(
    role: ReadinessRole,
    request: AdmissionRequest,
) -> Result<AdmissionResult> {
    if request.schema != ADMISSION_REQUEST_SCHEMA {
        bail!("unsupported admission request schema");
    }
    validate_admission_resource(&request)?;
    require_method(&request.method, &request.semantics)?;
    if !request.resource_spec.realization.as_json().is_null() {
        bail!("readiness publication unexpectedly carries a desired realization");
    }
    validate_resource_contexts(&request.resources)?;
    let observation_schema = request
        .contract
        .observation_discriminator()
        .context("selected readiness method has no exact observation discriminator")?;

    let selected = selected_target(&request.resource_spec.value)?;
    let manager = PinnedSystemdManager::connect().await?;
    let inspection = inspect(
        &manager,
        role,
        observation_schema,
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

pub(crate) async fn invoke(
    role: ReadinessRole,
    invocation: Invocation,
) -> Result<InvocationResult> {
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
    let observation_schema = invocation
        .contract
        .observation_discriminator()
        .context("selected readiness method has no exact observation discriminator")?;

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

    let selected = selected_target(&bound.resource_spec.value)?;
    let manager = PinnedSystemdManager::connect().await?;
    if manager.incarnation().bus_id() != provider.manager_bus_id
        || manager.incarnation().owner() != provider.manager_owner
    {
        bail!("systemd manager changed after admission");
    }
    let inspection = inspect(
        &manager,
        role,
        observation_schema,
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
    role: ReadinessRole,
    observation_schema: &str,
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
    let inactive_state = role.inactive_state();
    let state = match active_state {
        Some(UnitActiveState::Active | UnitActiveState::Reloading) => "ready",
        Some(UnitActiveState::Failed) => "failed",
        Some(UnitActiveState::Inactive) => inactive_state,
        Some(_) | None => "unknown",
    };
    let observation = value(&serde_json::json!({
        "schema": observation_schema,
        "expected": selected_expected(expected)?,
        "state": state,
    }))?;

    Ok(Inspection {
        observation,
        unit_identity,
    })
}

fn require_method(method: &MethodReference, semantics: &MethodSemantics) -> Result<()> {
    if method.method.as_str() != "observe" {
        bail!("handler invocation selects an unsupported readiness method");
    }
    if *semantics != MethodSemantics::ordinary(AccessMode::Read) {
        bail!("readiness method carries mismatched semantics");
    }
    Ok(())
}

fn selected_target(expected: &AbilityValue) -> Result<&str> {
    expected
        .as_json()
        .get("systemd_unit")
        .and_then(|unit| unit.get("unit_name"))
        .and_then(serde_json::Value::as_str)
        .filter(|name| {
            let suffix = name.rsplit_once('.').map(|(_, suffix)| suffix);
            !name.is_empty()
                && name.len() <= 255
                && name.chars().all(|character| {
                    character.is_ascii_alphanumeric() || "_.@:-".contains(character)
                })
                && matches!(
                    suffix,
                    Some(
                        "service"
                            | "socket"
                            | "target"
                            | "timer"
                            | "path"
                            | "mount"
                            | "automount"
                            | "swap"
                            | "device"
                    )
                )
        })
        .ok_or_else(|| anyhow::anyhow!("readiness effect has no valid systemd unit identity"))
}

fn selected_expected(expected: &AbilityValue) -> Result<&serde_json::Value> {
    expected
        .as_json()
        .get("expected")
        .ok_or_else(|| anyhow::anyhow!("readiness effect has no provider-neutral expected value"))
}

#[cfg(test)]
mod tests {
    use aos_ability_model::AbilityValue;

    use super::{ReadinessRole, selected_expected, selected_target};

    #[test]
    fn readiness_effects_carry_checked_package_owned_manager_targets() {
        let online = AbilityValue::new(serde_json::json!({
            "expected": {
                "scope": "configured-connectivity",
                "address_families": ["ipv4"],
            },
            "systemd_unit": {"unit_name": "network-online.target"},
        }))
        .expect("request is bounded");
        let prepared = AbilityValue::new(serde_json::json!({
            "expected": {
                "scope": "stack-prepared",
                "address_families": ["ipv4"],
            },
            "systemd_unit": {"unit_name": "network-pre.target"},
        }))
        .expect("request is bounded");
        let filesystems = AbilityValue::new(serde_json::json!({
            "expected": {"scope": "local-filesystems"},
            "systemd_unit": {"unit_name": "local-fs.target"},
        }))
        .expect("request is bounded");
        let milestone = AbilityValue::new(serde_json::json!({
            "expected": {"milestone": "interactive-console"},
            "systemd_unit": {"unit_name": "getty.target"},
        }))
        .expect("request is bounded");
        let runtime_entries = AbilityValue::new(serde_json::json!({
            "expected": {"scope": "runtime-entries"},
            "systemd_unit": {"unit_name": "systemd-tmpfiles-setup.service"},
        }))
        .expect("request is bounded");

        assert_eq!(
            selected_target(&online).expect("online target"),
            "network-online.target"
        );
        assert_eq!(
            selected_target(&prepared).expect("prepared target"),
            "network-pre.target"
        );
        assert_eq!(
            selected_target(&filesystems).expect("filesystem target"),
            "local-fs.target"
        );
        assert_eq!(
            selected_target(&milestone).expect("milestone target"),
            "getty.target"
        );
        assert_eq!(
            selected_expected(&milestone).expect("neutral milestone"),
            &serde_json::json!({"milestone": "interactive-console"})
        );
        assert_eq!(
            selected_target(&runtime_entries).expect("runtime population target"),
            "systemd-tmpfiles-setup.service"
        );

        assert_eq!(ReadinessRole::Network.inactive_state(), "configuring");
        assert_eq!(
            ReadinessRole::ActivationMilestone.inactive_state(),
            "pending"
        );
        assert_eq!(ReadinessRole::SystemMilestone.inactive_state(), "pending");
    }
}
