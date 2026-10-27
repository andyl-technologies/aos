//! Captures the real checked Start decision without selecting a recipe or lease.
//!
//! These serializable originals are historical data. Only the authenticated
//! evaluator and its retained peer can produce the fresh capture; decoding a
//! retained carrier cannot revive that evaluator or its TLS session.

use crate::Journal;
use crate::cli_model::PublicMutationAuthorizationV1;
use crate::cli_model::authorization_adapter::CurrentCapabilityDecisionV1;
use crate::public_api_session::PublicApiPeer;
use crate::public_mutation_compiler::PublicMutationAuthorizationErrorV1;

pub(crate) use aos_sandbox_protocol::public_api::mutation_history::CheckedStartAuthorityV2;

pub(crate) fn capture_checked_start_authority(
    journal: &mut Journal,
    peer: &PublicApiPeer,
    decision: &CurrentCapabilityDecisionV1,
    authorization: PublicMutationAuthorizationV1,
    original_request: &[u8],
) -> Result<CheckedStartAuthorityV2, PublicMutationAuthorizationErrorV1> {
    let rejected = || PublicMutationAuthorizationErrorV1::Rejected;
    peer.recheck().map_err(|_| rejected())?;
    journal
        .validate_held_protected_names()
        .map_err(|_| rejected())?;
    let coordinates = authorization.original_coordinates().ok_or_else(rejected)?;
    if decision.original_coordinates(coordinates.session_commitment()) != coordinates
        || decision.authorized_wall_seconds() != authorization.accepted_wall_seconds()
        || decision.policy().generation() != authorization.policy_generation()
    {
        return Err(rejected());
    }
    if original_request
        .len()
        .checked_add(decision.policy().canonical_policy().len())
        .is_none_or(|length| length > 1_048_576)
    {
        return Err(rejected());
    }

    let captured = CheckedStartAuthorityV2::from_historical_parts((
        decision.capability().clone(),
        coordinates,
        peer.principal(),
        peer.project(),
        authorization.accepted_wall_seconds(),
        decision.policy().descriptor().clone(),
        decision.policy().canonical_policy().to_vec(),
        original_request.to_vec(),
        peer.original_trust_coordinates().map_err(|_| rejected())?,
    ));
    captured.validate().map_err(|_| rejected())?;
    peer.recheck().map_err(|_| rejected())?;
    journal
        .validate_held_protected_names()
        .map_err(|_| rejected())?;
    Ok(captured)
}
