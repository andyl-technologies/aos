//! Exact checked-plan provider state-transfer contracts.
//!
//! A transfer is supported only when the operation's checked route resolves to
//! one persistent pure-composition owner with an authenticated state format and
//! one exact terminal handler. The returned contract retains the complete
//! operation so callers can durably bind a pre-effect rejection to the same
//! method and resource that runtime admission would execute.

use aos_ability_model::{
    InstanceId, InterfaceKey, Operation, PlanId, ProviderImplementationReference,
    ProviderStateFormat, ResourceLifetime,
};
use aos_ability_validate::CheckedEffectPlan;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::inventory::provider_state_transfer_owner;
use super::GenerationAbilityStoreError;
use crate::config_eval::native_adapter_surface::matches_provider_contract;

/// Identifies the canonical provider state-transfer inspection contract.
pub const PROVIDER_STATE_TRANSFER_CONTRACT_SCHEMA: &str =
    "aos.ability.provider-state-transfer-contract/v1";

/// Records the checked-plan disposition for one exact operation route.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderStateTransferContract {
    /// Identifies this contract's schema and semantics.
    pub schema: String,
    /// Identifies the checked effect plan inspected by the contract.
    pub plan: PlanId,
    /// Retains the exact candidate route, method, target, and authority.
    pub operation: Operation,
    /// States whether the route supplies a transferable provider-state owner.
    pub disposition: ProviderStateTransferDisposition,
}

impl ProviderStateTransferContract {
    /// Encodes this contract in the canonical AOS JSON dialect.
    ///
    /// # Errors
    ///
    /// Returns an error when the contract cannot be canonically encoded.
    pub fn canonical_bytes(&self) -> anyhow::Result<Vec<u8>> {
        aos_contract::canonical::to_vec(self)
    }

    /// Computes the domain-separated contract identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the contract cannot be canonically encoded.
    pub fn digest(&self) -> anyhow::Result<Sha256Digest> {
        Sha256Digest::of_canonical(PROVIDER_STATE_TRANSFER_CONTRACT_SCHEMA, self)
    }
}

/// Classifies whether an exact checked operation can receive provider state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ProviderStateTransferDisposition {
    /// The checked route selects one authenticated transferable owner.
    Supported {
        /// Identifies the selected owner and terminal handler.
        owner: ProviderStateTransferOwner,
    },
    /// The checked route cannot participate in provider-state adoption.
    Unsupported {
        /// Records the fail-closed reason and exact checked lifetimes.
        rejection: ProviderStateTransferRejection,
    },
}

/// Identifies the complete durable owner and terminal-handler contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderStateTransferOwner {
    /// Identifies the logical provider that owns persistent state.
    pub provider: InstanceId,
    /// Pins the authenticated package declaring the owner implementation.
    pub package: Sha256Digest,
    /// Identifies the owner's public composition interface.
    pub interface: InterfaceKey,
    /// Pins the authenticated owner implementation artifact and descriptor.
    pub implementation: ProviderImplementationReference,
    /// Declares the persistent-state format eligible for adoption.
    pub state_format: ProviderStateFormat,
    /// Identifies the terminal provider that executes the exact method.
    pub handler_provider: InstanceId,
    /// Pins the authenticated package declaring the terminal handler.
    pub handler_package: Sha256Digest,
    /// Identifies the terminal handler's public interface.
    pub handler_interface: InterfaceKey,
    /// Pins the authenticated terminal implementation.
    pub handler_implementation: ProviderImplementationReference,
}

/// Records why an exact checked operation cannot receive provider state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderStateTransferRejection {
    /// Classifies the missing production contract.
    pub reason: ProviderStateTransferRejectionReason,
    /// Retains the operation target lifetime checked before any effect.
    pub target_lifetime: ResourceLifetime,
    /// Retains the consumer request lifetime checked before any effect.
    pub request_lifetime: ResourceLifetime,
    /// Retains the selected binding lifetime checked before any effect.
    pub binding_lifetime: ResourceLifetime,
}

/// Classifies fail-closed provider state-transfer rejection reasons.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderStateTransferRejectionReason {
    /// At least one checked route component does not retain persistent state.
    NonPersistentLifetime,
    /// The exact target does not belong to the selected route's consumer.
    NoResourceOwner,
    /// No exact pure owner declares an authenticated state format for the target.
    MissingAuthenticatedStateFormat,
}

/// Inspects state-transfer support for one exact checked operation.
///
/// This function performs no provider effect. A caller can therefore persist
/// an `Unsupported` result before dispatch while retaining the exact checked
/// operation and the plan identity that authorized the attempted route.
///
/// # Errors
///
/// Returns an error when `operation` is not the exact member of `plan`, its
/// checked binding or request disappeared, or owner selection is ambiguous.
pub fn inspect_provider_state_transfer(
    plan: &CheckedEffectPlan,
    operation: &Operation,
) -> Result<ProviderStateTransferContract, GenerationAbilityStoreError> {
    if plan.operation(&operation.key) != Some(operation) {
        return Err(GenerationAbilityStoreError::Conflict(
            "provider state-transfer inspection requires an exact checked operation".to_string(),
        ));
    }

    let binding = plan
        .binding_plan()
        .binding(&operation.binding)
        .ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "provider state-transfer operation lost its checked binding".to_string(),
            )
        })?;
    let request = plan
        .binding_plan()
        .document()
        .requests
        .iter()
        .find(|request| request.id == binding.request)
        .ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "provider state-transfer binding lost its checked request".to_string(),
            )
        })?;

    let selected = provider_state_transfer_owner(plan, operation)?;
    let disposition = if let Some(owner) = selected {
        ProviderStateTransferDisposition::Supported { owner }
    } else {
        let reason = if operation.target.lifetime != ResourceLifetime::Persistent
            || request.lifetime != ResourceLifetime::Persistent
            || binding.lifetime != ResourceLifetime::Persistent
        {
            ProviderStateTransferRejectionReason::NonPersistentLifetime
        } else if operation.target.resource.provider != binding.request.consumer {
            ProviderStateTransferRejectionReason::NoResourceOwner
        } else {
            ProviderStateTransferRejectionReason::MissingAuthenticatedStateFormat
        };
        ProviderStateTransferDisposition::Unsupported {
            rejection: ProviderStateTransferRejection {
                reason,
                target_lifetime: operation.target.lifetime,
                request_lifetime: request.lifetime,
                binding_lifetime: binding.lifetime,
            },
        }
    };

    Ok(ProviderStateTransferContract {
        schema: PROVIDER_STATE_TRANSFER_CONTRACT_SCHEMA.to_string(),
        plan: plan.id(),
        operation: operation.clone(),
        disposition,
    })
}

/// Inspects and verifies a state-transfer route against the native matrix surface.
///
/// This qualification entry point first runs the production state-transfer
/// inspection, then checks its exact operation, request, binding, and
/// authenticated state format against the generated native method contract.
///
/// # Errors
///
/// Returns an error under the conditions documented by
/// [`inspect_provider_state_transfer`], or when the checked route differs from
/// the native matrix provider contract compiled into this binary.
pub fn inspect_native_adapter_provider_state_transfer(
    plan: &CheckedEffectPlan,
    operation: &Operation,
) -> Result<ProviderStateTransferContract, GenerationAbilityStoreError> {
    let contract = inspect_provider_state_transfer(plan, operation)?;
    let binding = plan
        .binding_plan()
        .binding(&operation.binding)
        .ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "native adapter state-transfer operation lost its checked binding".to_string(),
            )
        })?;
    let request = plan
        .binding_plan()
        .document()
        .requests
        .iter()
        .find(|request| request.id == binding.request)
        .ok_or_else(|| {
            GenerationAbilityStoreError::Conflict(
                "native adapter state-transfer binding lost its checked request".to_string(),
            )
        })?;
    let state_format = match &contract.disposition {
        ProviderStateTransferDisposition::Supported { owner } => {
            Some(owner.state_format.descriptor)
        }
        ProviderStateTransferDisposition::Unsupported { .. } => None,
    };

    if !matches_provider_contract(
        operation.interface.name.as_str(),
        operation.interface.abi.get(),
        operation.interface.descriptor,
        operation.method.as_str(),
        operation.target.lifetime,
        request.lifetime,
        binding.lifetime,
        state_format,
    ) {
        return Err(GenerationAbilityStoreError::Conflict(
            "checked state-transfer route differs from the native adapter provider contract"
                .to_string(),
        ));
    }

    Ok(contract)
}

#[cfg(test)]
mod tests {
    use aos_ability_validate::test_support::{
        checked_stateful_owner_effect_plan, checked_systemd_manager_effect_plan,
    };

    use super::*;

    #[test]
    fn exact_systemd_manager_route_rejects_state_transfer() {
        let plan = checked_systemd_manager_effect_plan();
        let operation = &plan.operations()[0];

        let contract = inspect_native_adapter_provider_state_transfer(&plan, operation)
            .expect("checked systemd manager transfer contract");

        assert_eq!(contract.plan, plan.id());
        assert_eq!(contract.operation, *operation);
        assert!(matches!(
            contract.disposition,
            ProviderStateTransferDisposition::Unsupported { .. }
        ));
        assert!(!contract
            .canonical_bytes()
            .expect("canonical contract")
            .is_empty());
    }

    #[test]
    fn exact_stateful_owner_route_exposes_its_authenticated_contract() {
        let plan = checked_stateful_owner_effect_plan();
        let operation = &plan.operations()[0];

        let contract = inspect_provider_state_transfer(&plan, operation)
            .expect("checked stateful owner transfer contract");

        let ProviderStateTransferDisposition::Supported { owner } = contract.disposition else {
            panic!("stateful owner route was rejected");
        };
        assert_eq!(owner.provider, operation.target.resource.provider);
        assert_eq!(owner.handler_interface, operation.interface);
        assert_eq!(owner.state_format.artifact, owner.implementation.artifact);
    }

    #[test]
    fn inspection_rejects_an_operation_outside_the_checked_plan() {
        let plan = checked_systemd_manager_effect_plan();
        let mut operation = plan.operations()[0].clone();
        operation.method =
            aos_ability_model::LocalKey::new("forged").expect("valid forged method key");

        let error = inspect_provider_state_transfer(&plan, &operation)
            .expect_err("forged operation must fail closed");

        assert!(error.to_string().contains("exact checked operation"));
    }
}
