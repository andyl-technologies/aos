//! Original opaque operation bounds beneath closed baseline wire requests.

use super::{VendorCnpAction, VendorCnpIdentity, refused};
use crate::node_contract::{ExactBoundaryPolicy, OperationFailure, OperationRequest};
use crucible_node_provider::bodies::{BeginArguments, BoundaryPolicy, RequestBody};

pub(super) fn validate_original(
    identity: &VendorCnpIdentity,
    action: &VendorCnpAction<'_>,
    body: &RequestBody,
) -> Result<(), OperationFailure> {
    let Some(original) = action.original() else {
        return Ok(());
    };
    let activation = original.activation().record();
    let authority = &identity.binding.authority;
    match (action, body) {
        (VendorCnpAction::Begin(_), RequestBody::Begin(begin)) => {
            if begin.activation_id.0.as_ref() != Some(&activation.activation_id)
                || begin.world_generation != activation.generation
                || begin.owner_generation != authority.owner_generation
            {
                return Err(refused(
                    "vendor Begin changed original activation/generation",
                ));
            }
            let arguments = begin.decoded_arguments().map_err(super::contract)?;
            validate_bounds(original.request(), &arguments)?;
            let expected_participants = match &arguments {
                BeginArguments::Capture(_) => {
                    &identity.binding.compatibility.capture_owner.participant_ids
                }
                _ => {
                    &identity
                        .binding
                        .compatibility
                        .execution_owner
                        .participant_ids
                }
            };
            let participants = match &arguments {
                BeginArguments::ExactRun(args) | BeginArguments::BoundarySettle(args) => {
                    if args.grant_id != *original.token().operation()
                        || args.realization_id != authority.realization_id
                        || args.activation_id != activation.activation_id
                        || args.world_generation != activation.generation
                        || args.owner_generation != authority.owner_generation
                        || args.input_epoch != authority.input_epoch
                    {
                        return Err(refused("vendor exact grant changed original live scope"));
                    }
                    &args.participant_ids
                }
                BeginArguments::QuantumBegin(args) => {
                    let OperationRequest::QuantumBegin { window, .. } = original.request() else {
                        return Err(refused("vendor quantum grant lacks original window"));
                    };
                    if args.grant_id != *window
                        || args.realization_id != authority.realization_id
                        || args.activation_id != activation.activation_id
                        || args.world_generation != activation.generation
                        || args.owner_generation != authority.owner_generation
                        || args.input_epoch != authority.input_epoch
                        || args.policy_hash
                            != identity
                                .binding
                                .compatibility
                                .operating_contract
                                .policy_ref
                                .hash
                    {
                        return Err(refused("vendor quantum grant changed original live scope"));
                    }
                    &args.participant_ids
                }
                BeginArguments::Pause(args) => &args.participant_ids,
                BeginArguments::Capture(args) => &args.participant_ids,
                BeginArguments::Shutdown(args) => &args.participant_ids,
                BeginArguments::PrepareRestore(_) => {
                    return Err(refused(
                        "restoration requires separate installed native admission",
                    ));
                }
            };
            if participants != expected_participants {
                return Err(refused(
                    "vendor Begin changed complete original participants",
                ));
            }
        }
        (VendorCnpAction::Close(_), RequestBody::QuantumClose(close)) => {
            let OperationRequest::QuantumBegin { window, end, .. } = original.request() else {
                return Err(refused("vendor closure lacks original quantum window"));
            };
            if close.grant_id != *window
                || close.cut != *end
                || close.activation_id != activation.activation_id
                || close.world_generation != activation.generation
                || close.owner_generation != authority.owner_generation
                || close.input_epoch != authority.input_epoch
                || close.participant_ids
                    != identity
                        .binding
                        .compatibility
                        .execution_owner
                        .participant_ids
                || close.policy_hash
                    != identity
                        .binding
                        .compatibility
                        .operating_contract
                        .policy_ref
                        .hash
            {
                return Err(refused(
                    "vendor closure changed original window/cut/live scope",
                ));
            }
        }
        _ => {}
    }
    // Owner-binding hashes and translated immutable input authorizations remain
    // exact installed source-codec obligations; no digest-to-body inference occurs.
    Ok(())
}

fn validate_bounds(
    request: &OperationRequest,
    arguments: &BeginArguments,
) -> Result<(), OperationFailure> {
    let valid = match (request, arguments) {
        (
            OperationRequest::ExactRun {
                start,
                limit,
                boundary_policy,
            },
            BeginArguments::ExactRun(args),
        ) => {
            let policy = match boundary_policy {
                ExactBoundaryPolicy::HorizonPark => BoundaryPolicy::OrdinaryStop,
                ExactBoundaryPolicy::InputBlockedPark => BoundaryPolicy::InputBlockedPark,
            };
            args.start == *start && args.limit == *limit && args.boundary_policy == policy
        }
        (
            OperationRequest::BoundarySettle { start, limit },
            BeginArguments::BoundarySettle(args),
        ) => args.start == *start && args.limit == *limit,
        (
            OperationRequest::QuantumBegin {
                start,
                end,
                host_budget,
                ..
            },
            BeginArguments::QuantumBegin(args),
        ) => {
            args.from_ps == start.time_ps
                && args.until_ps == end.time_ps
                && u64::try_from(host_budget.as_nanos()).ok() == Some(args.wall_budget_ns.get())
        }
        (OperationRequest::Pause, BeginArguments::Pause(_))
        | (OperationRequest::Capture, BeginArguments::Capture(_))
        | (OperationRequest::Shutdown, BeginArguments::Shutdown(_)) => true,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(refused(
            "vendor Begin changed original operation kind or exclusive bounds",
        ))
    }
}

#[cfg(test)]
#[path = "scope_tests.rs"]
mod tests;
