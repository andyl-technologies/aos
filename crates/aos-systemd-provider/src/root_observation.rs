//! Stage-entry observation of the existing systemd manager facility.
//!
//! All terminal systemd handler roles use the same pinned manager connection.
//! Resource-specific readiness remains in the effect plan and handler methods;
//! this probe establishes only that the selected manager is currently reachable
//! and identifies its exact bus lifetime and owner.

use anyhow::{Result, ensure};
use aos_ability_model::document::{FreshnessCondition, ProviderState};
use aos_ability_model::{AbilityValue, IncarnationId, RevisionId};
use aos_contract::Sha256Digest;
use aos_provider_protocol::{
    ROOT_OBSERVATION_REQUEST_SCHEMA, ROOT_OBSERVATION_RESULT_SCHEMA, RootObservationRequest,
    RootObservationResult, validate_root_observation,
};
use aos_systemd::PinnedSystemdManager;
use std::fs;

use crate::HandlerRole;

pub(super) async fn observe(
    _role: HandlerRole,
    request: RootObservationRequest,
) -> Result<RootObservationResult> {
    ensure!(
        request.schema == ROOT_OBSERVATION_REQUEST_SCHEMA
            && request.maximum_age_millis > 0
            && request.control.attempt_remaining_millis > 0
            && !request.control.cancelled,
        "invalid systemd root observation request"
    );
    aos_provider_protocol::validate_boot_id(&request.boot_id)?;
    let native_boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    ensure!(
        native_boot_id.trim() == request.boot_id,
        "systemd root observation belongs to another boot"
    );

    let manager = PinnedSystemdManager::connect().await?;
    let native = manager.incarnation();
    let incarnation = IncarnationId::new(native.token())?;
    let generation = RevisionId(Sha256Digest::separated(
        "aos.systemd.manager-incarnation/v1",
        native.token().as_bytes(),
    ));
    let result = RootObservationResult {
        schema: ROOT_OBSERVATION_RESULT_SCHEMA.to_string(),
        challenge: request.challenge,
        provider: request.provider.clone(),
        interface: request.interface.clone(),
        implementation: request.implementation.clone(),
        policy_revision: request.policy_revision,
        boot_id: request.boot_id.clone(),
        state: ProviderState::Available,
        incarnation: Some(incarnation),
        freshness: FreshnessCondition {
            generation,
            max_age_millis: request.maximum_age_millis,
        },
        evidence: AbilityValue::new(serde_json::json!({
            "schema": "aos.systemd.manager-root-observation/v1",
            "bus_id": native.bus_id(),
            "owner": native.owner(),
        }))?,
    };
    validate_root_observation(&request, &result)?;
    Ok(result)
}
