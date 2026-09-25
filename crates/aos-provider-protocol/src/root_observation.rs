//! Effect-free observation of an existing provider at stage entry.
//!
//! A package handler may attest only to the exact implementation selected by
//! the sealed source template. The stage adapter authenticates its executable,
//! supplies a fresh challenge, and checks the handler's native observation
//! before constructing the trusted environment document.

use anyhow::{Result, ensure};
use aos_ability_model::document::{FreshnessCondition, ProviderState};
use aos_ability_model::{
    AbilityValue, IncarnationId, InstanceId, InterfaceKey, ProviderImplementationReference,
    RevisionId,
};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::InvocationControl;

/// Identifies a request to observe an existing root provider.
pub const ROOT_OBSERVATION_REQUEST_SCHEMA: &str = "aos.primitive.root-observation-request/v1";

/// Identifies the package handler's bounded root observation.
pub const ROOT_OBSERVATION_RESULT_SCHEMA: &str = "aos.primitive.root-observation-result/v1";

/// Selects one exact terminal implementation for an effect-free root probe.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootObservationRequest {
    /// Carries [`ROOT_OBSERVATION_REQUEST_SCHEMA`].
    pub schema: String,
    /// Names the selected fixed-point provider instance.
    pub provider: InstanceId,
    /// Pins the exact interface exposed to its selected consumer.
    pub interface: InterfaceKey,
    /// Pins the selected package implementation and handler artifact.
    pub implementation: ProviderImplementationReference,
    /// Pins the policy revision used by the source-stage template.
    pub policy_revision: RevisionId,
    /// Names the current boot whose native facilities are being observed.
    pub boot_id: String,
    /// Challenges this observation attempt so a prior response cannot be reused.
    pub challenge: Sha256Digest,
    /// Caps the duration for which the observation may be considered fresh.
    pub maximum_age_millis: u64,
    /// Bounds the effect-free handler invocation.
    pub control: InvocationControl,
}

/// Reports the native state of one selected root implementation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootObservationResult {
    /// Carries [`ROOT_OBSERVATION_RESULT_SCHEMA`].
    pub schema: String,
    /// Echoes the challenge of the current invocation.
    pub challenge: Sha256Digest,
    /// Echoes the exact selected provider instance.
    pub provider: InstanceId,
    /// Echoes the selected interface contract.
    pub interface: InterfaceKey,
    /// Echoes the selected implementation and handler artifact.
    pub implementation: ProviderImplementationReference,
    /// Echoes the selected policy revision.
    pub policy_revision: RevisionId,
    /// Echoes the boot identity verified by the native handler.
    pub boot_id: String,
    /// Reports availability established by this native observation.
    pub state: ProviderState,
    /// Pins the live assignment when the provider is available.
    pub incarnation: Option<IncarnationId>,
    /// Identifies a stable observation generation within the provider lifetime.
    pub freshness: FreshnessCondition,
    /// Carries evidence produced by the authenticated package's native probe.
    pub evidence: AbilityValue,
}

/// Checks one result against the exact selected root probe.
///
/// This validates the shared wire contract. The authenticated package handler
/// owns the native probe; the stage adapter measures observation age before
/// marking the provider available in the environment document.
///
/// # Errors
///
/// Returns an error for a changed identity, challenge, policy, invalid
/// availability state, or freshness claim beyond the requested ceiling.
pub fn validate_root_observation(
    request: &RootObservationRequest,
    result: &RootObservationResult,
) -> Result<()> {
    ensure!(
        request.schema == ROOT_OBSERVATION_REQUEST_SCHEMA
            && result.schema == ROOT_OBSERVATION_RESULT_SCHEMA,
        "root observation has an unsupported schema"
    );
    ensure!(
        request.implementation.handler.is_some(),
        "root observation requires a selected terminal handler"
    );
    validate_boot_id(&request.boot_id)?;
    ensure!(
        result.challenge == request.challenge
            && result.provider == request.provider
            && result.interface == request.interface
            && result.implementation == request.implementation
            && result.policy_revision == request.policy_revision
            && result.boot_id == request.boot_id,
        "root observation differs from the selected implementation or invocation"
    );
    ensure!(
        matches!(
            result.state,
            ProviderState::Available | ProviderState::Unavailable
        ),
        "root observation reports a nonterminal provider state"
    );
    ensure!(
        (result.state == ProviderState::Available) == result.incarnation.is_some(),
        "root observation availability and incarnation disagree"
    );
    ensure!(
        request.maximum_age_millis > 0
            && request.control.attempt_remaining_millis > 0
            && !request.control.cancelled
            && result.freshness.max_age_millis > 0
            && result.freshness.max_age_millis <= request.maximum_age_millis,
        "root observation freshness exceeds the requested bound"
    );
    ensure!(
        !result.evidence.as_json().is_null(),
        "root observation has no native evidence"
    );
    Ok(())
}

/// Checks the canonical lowercase boot UUID used by root observations.
///
/// # Errors
///
/// Returns an error when the identity is not a lowercase hyphenated UUID.
pub fn validate_boot_id(boot_id: &str) -> Result<()> {
    ensure!(boot_id.len() == 36, "boot identity is not a canonical UUID");
    ensure!(
        boot_id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        }),
        "boot identity is not a lowercase canonical UUID"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use aos_ability_model::document::{FreshnessCondition, ProviderState};
    use aos_ability_model::{
        AbilityValue, IncarnationId, InstanceId, InterfaceKey, InterfaceName,
        ProviderImplementationReference, RevisionId,
    };
    use aos_contract::Sha256Digest;

    use super::{
        ROOT_OBSERVATION_REQUEST_SCHEMA, ROOT_OBSERVATION_RESULT_SCHEMA, RootObservationRequest,
        RootObservationResult, validate_root_observation,
    };
    use crate::InvocationControl;

    fn request() -> RootObservationRequest {
        let provider: InstanceId = serde_json::from_value(serde_json::json!({
            "environment": {"authority":"system-image","key":"test","stage":"initrd"},
            "key":"manager"
        }))
        .expect("provider identity");
        let implementation: ProviderImplementationReference =
            serde_json::from_value(serde_json::json!({
                "descriptor": Sha256Digest::of_bytes(b"implementation"),
                "artifact": {
                    "content": Sha256Digest::of_bytes(b"artifact"),
                    "store_path": "/nix/store/00000000000000000000000000000000-provider",
                    "nar_hash": Sha256Digest::of_bytes(b"nar"),
                    "closure": Sha256Digest::of_bytes(b"closure"),
                },
                "handler": "manager",
            }))
            .expect("implementation reference");

        RootObservationRequest {
            schema: ROOT_OBSERVATION_REQUEST_SCHEMA.to_string(),
            provider,
            interface: InterfaceKey {
                name: InterfaceName::new("aos.test.manager").expect("interface name"),
                abi: NonZeroU32::MIN,
                descriptor: Sha256Digest::of_bytes(b"interface"),
            },
            implementation,
            policy_revision: RevisionId(Sha256Digest::of_bytes(b"policy")),
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
            challenge: Sha256Digest::of_bytes(b"current invocation"),
            maximum_age_millis: 1_000,
            control: InvocationControl {
                attempt_remaining_millis: 1_000,
                recovery_remaining_millis: 1_000,
                cancelled: false,
            },
        }
    }

    fn result(request: &RootObservationRequest) -> RootObservationResult {
        RootObservationResult {
            schema: ROOT_OBSERVATION_RESULT_SCHEMA.to_string(),
            challenge: request.challenge,
            provider: request.provider.clone(),
            interface: request.interface.clone(),
            implementation: request.implementation.clone(),
            policy_revision: request.policy_revision,
            boot_id: request.boot_id.clone(),
            state: ProviderState::Available,
            incarnation: Some(IncarnationId::new("manager-boot-1").expect("incarnation")),
            freshness: FreshnessCondition {
                generation: RevisionId(Sha256Digest::of_bytes(b"manager generation")),
                max_age_millis: 500,
            },
            evidence: AbilityValue::new(serde_json::json!({"manager":"connected"}))
                .expect("native evidence"),
        }
    }

    #[test]
    fn root_observation_is_bound_to_the_current_selected_handler() {
        let request = request();
        let observed = result(&request);
        validate_root_observation(&request, &observed).expect("exact root observation");

        let mut changed = observed.clone();
        changed.challenge = Sha256Digest::of_bytes(b"prior invocation");
        assert!(validate_root_observation(&request, &changed).is_err());

        changed = observed.clone();
        changed.implementation.descriptor = Sha256Digest::of_bytes(b"other implementation");
        assert!(validate_root_observation(&request, &changed).is_err());

        changed = observed.clone();
        changed.boot_id = "11234567-89ab-cdef-0123-456789abcdef".to_string();
        assert!(validate_root_observation(&request, &changed).is_err());

        changed = observed.clone();
        changed.incarnation = None;
        assert!(validate_root_observation(&request, &changed).is_err());

        changed = observed;
        changed.freshness.max_age_millis = 1_001;
        assert!(validate_root_observation(&request, &changed).is_err());
    }
}
