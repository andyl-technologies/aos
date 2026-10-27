//! Retains actual authenticated admission inputs under the Controller writer.

use crate::Journal;
use crate::cli_model::PublicMutationAuthorizationV1;
use crate::cli_model::authorization_adapter::CurrentCapabilityDecisionV1;
use crate::public_api_session::PublicApiPeer;
use crate::public_mutation_compiler::PublicMutationAuthorizationErrorV1;

pub(crate) use aos_sandbox_protocol::public_api::mutation_history::AdmissionAuthorityV1;

pub(crate) fn capture_admission_authority(
    journal: &mut Journal,
    peer: &PublicApiPeer,
    decision: &CurrentCapabilityDecisionV1,
    authorization: PublicMutationAuthorizationV1,
) -> Result<AdmissionAuthorityV1, PublicMutationAuthorizationErrorV1> {
    let rejected = || PublicMutationAuthorizationErrorV1::Rejected;
    peer.recheck().map_err(|_| rejected())?;
    journal
        .validate_held_protected_names()
        .map_err(|_| rejected())?;

    // This is the actual decision retained through authenticated request
    // binding, not a second grant evaluation or a later registry lookup.
    let coordinates = authorization.original_coordinates().ok_or_else(rejected)?;
    if decision.original_coordinates(coordinates.session_commitment()) != coordinates
        || decision.authorized_wall_seconds() != authorization.accepted_wall_seconds()
        || decision.policy().generation() != authorization.policy_generation()
    {
        return Err(rejected());
    }
    let capability = decision.capability().clone();
    let claims = capability.claims();
    let policy = decision.policy();
    if claims.holder != peer.principal()
        || claims.channel_binding != peer.key_binding()
        || claims.project != peer.project()
    {
        return Err(rejected());
    }

    let (_, revision, _, request, _) = authorization.provenance().commitments();
    let captured = AdmissionAuthorityV1::from_historical_parts((
        capability,
        peer.principal(),
        peer.key_binding(),
        peer.project(),
        authorization.accepted_wall_seconds(),
        policy.generation(),
        policy.descriptor().clone(),
        coordinates.controller_generation(),
        revision.digest(),
        request.digest(),
    ));
    captured.validate().map_err(|_| rejected())?;
    peer.recheck().map_err(|_| rejected())?;
    journal
        .validate_held_protected_names()
        .map_err(|_| rejected())?;
    Ok(captured)
}
