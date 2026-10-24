//! Transfers only actual original owning wrappers into authenticated retirement.
//!
//! A missing restored world requires the factory's still-present unused lease;
//! it never substitutes for activation, containment or reclamation evidence.

use super::{NodeObservationServiceError, Owner, refused};

pub(super) fn begin(
    owner: &mut Owner,
    native_preparation_started: bool,
) -> Result<bool, NodeObservationServiceError> {
    match owner {
        Owner::Initial {
            preservation,
            runtime,
            activation,
            graph,
        } => {
            let Some(activation) = activation.as_ref() else {
                return Ok(false);
            };
            let preservation = preservation
                .take()
                .ok_or_else(|| refused("Root retirement policy absent"))?;
            let runtime = runtime
                .take()
                .ok_or_else(|| refused("Root retirement runtime absent"))?;
            match (*preservation).begin_retirement(*runtime, graph, activation) {
                Ok(retirement) => *owner = Owner::Retiring(Some(Box::new(retirement))),
                Err(failure) => {
                    let failure = *failure;
                    if let Owner::Initial {
                        preservation,
                        runtime,
                        ..
                    } = owner
                    {
                        *preservation = Some(Box::new(failure.preservation));
                        *runtime = Some(Box::new(failure.runtime));
                    }
                    return Err(refused(failure.error));
                }
            }
        }
        Owner::Restored { plan, world } => {
            let plan = plan
                .take()
                .ok_or_else(|| refused("Root restored retirement policy absent"))?;
            let Some(world) = world.take() else {
                match (*plan).begin_unstarted_retirement() {
                    Ok(retirement) => *owner = Owner::Retiring(Some(Box::new(retirement))),
                    Err(failure) => {
                        let failure = *failure;
                        if let Owner::Restored { plan, .. } = owner {
                            *plan = Some(Box::new(failure.restore));
                        }
                        return Err(refused(failure.error));
                    }
                }
                return Ok(true);
            };
            match (*plan).begin_retirement(*world) {
                Ok(retirement) => *owner = Owner::Retiring(Some(Box::new(retirement))),
                Err(failure) => {
                    let failure = *failure;
                    if let Owner::Restored { plan, world } = owner {
                        *plan = Some(Box::new(failure.restore));
                        *world = Some(Box::new(failure.restored));
                    }
                    return Err(refused(failure.error));
                }
            }
        }
        Owner::Empty if native_preparation_started => {
            // The producer's failed-preparation supervisor owns any
            // uncertain native child. Without its exact returned
            // retirement handle this actor cannot invent release.
            return Ok(false);
        }
        Owner::Empty => *owner = Owner::Released,
        Owner::Retiring(_) | Owner::Released => {}
    }
    Ok(true)
}
