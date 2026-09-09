//! Deterministic assembly of validated provider fragments.

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::{BindingRequest, DesiredStateDocument, InstanceId, RequestId};

use super::{CompositionError, CompositionFragment};

pub(super) fn merge_fragments(
    seed: &DesiredStateDocument,
    fragments: Vec<(InstanceId, CompositionFragment)>,
) -> Result<DesiredStateDocument, CompositionError> {
    let mut desired = seed.clone();
    let mut requests: BTreeMap<RequestId, BindingRequest> = desired
        .child_requests
        .drain(..)
        .map(|request| (request.id.clone(), request))
        .collect();
    let mut contribution_slots: BTreeSet<_> = desired
        .contributions
        .iter()
        .map(|contribution| (contribution.aggregate.clone(), contribution.slot.clone()))
        .collect();
    let mut resources: BTreeMap<_, _> = desired
        .resources
        .drain(..)
        .map(|revision| (revision.resource.clone(), revision))
        .collect();
    let mut controllers: BTreeMap<_, _> = desired
        .controllers
        .drain(..)
        .map(|assignment| (assignment.resource.clone(), assignment))
        .collect();
    let mut outputs: BTreeMap<_, _> = desired
        .outputs
        .drain(..)
        .map(|output| {
            (
                (
                    output.aggregate.clone(),
                    output.interface.clone(),
                    output.port.clone(),
                ),
                output,
            )
        })
        .collect();

    for (provider, fragment) in fragments {
        for request in fragment.requests {
            if requests.insert(request.id.clone(), request).is_some() {
                return Err(CompositionError::InvalidFragment {
                    provider,
                    reason: "fragment duplicates a desired request identity".to_string(),
                });
            }
        }
        for contribution in fragment.contributions {
            if !contribution_slots
                .insert((contribution.aggregate.clone(), contribution.slot.clone()))
            {
                return Err(CompositionError::InvalidFragment {
                    provider,
                    reason: "fragment collides with an existing aggregate contribution slot"
                        .to_string(),
                });
            }
            desired.contributions.push(contribution);
        }
        for revision in fragment.resources {
            if resources
                .insert(revision.resource.clone(), revision)
                .is_some()
            {
                return Err(CompositionError::InvalidFragment {
                    provider,
                    reason: "fragment duplicates a desired resource identity".to_string(),
                });
            }
        }
        for output in fragment.outputs {
            let key = (
                output.aggregate.clone(),
                output.interface.clone(),
                output.port.clone(),
            );
            if outputs.insert(key, output).is_some() {
                return Err(CompositionError::InvalidFragment {
                    provider,
                    reason: "fragment duplicates a provider-qualified desired output".to_string(),
                });
            }
        }
        for assignment in fragment.controllers {
            if controllers
                .insert(assignment.resource.clone(), assignment)
                .is_some()
            {
                return Err(CompositionError::InvalidFragment {
                    provider,
                    reason: "fragment duplicates a controller assignment".to_string(),
                });
            }
        }
    }

    desired.child_requests = requests.into_values().collect();
    desired.resources = resources.into_values().collect();
    desired.controllers = controllers.into_values().collect();
    desired.outputs = outputs.into_values().collect();
    Ok(desired)
}
