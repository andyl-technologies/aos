//! Resolves authored condition demands before the existing owning actor admits work.

use super::{NodeObservationServiceError, NodePreservingDebugRequest, refused};
use crate::{
    node_observed_executor::{
        InstalledHostStateFactory, InstalledNodeCatalog, ResolvedCapabilityWorld,
    },
    node_scenario::NodeScenario,
};
use crucible::node_state::HostArchiveRecord;
use std::rc::Rc;

pub(super) fn resolve(
    catalog: &InstalledNodeCatalog,
    request: &NodePreservingDebugRequest,
    record: Option<&HostArchiveRecord>,
) -> Result<Option<ResolvedCapabilityWorld>, NodeObservationServiceError> {
    let Some(requirements) = &request.requirements else {
        return Ok(None);
    };
    let resolved = match record {
        Some(record) => catalog.resolve_condition_capabilities_from_archive(
            &request.selections,
            requirements.as_slice(),
            record,
        ),
        None => {
            catalog.resolve_condition_capabilities(&request.selections, requirements.as_slice())
        }
    }
    .map_err(refused)?;
    if resolved.scenario().canonical_bytes().map_err(refused)? != request.scenario.as_slice() {
        return Err(refused(
            "authored condition scenario differs from its original capability selection",
        ));
    }
    Ok(Some(resolved))
}

pub(super) fn factory(
    catalog: &InstalledNodeCatalog,
    request: &NodePreservingDebugRequest,
    resolved: Option<&ResolvedCapabilityWorld>,
    record: Option<&HostArchiveRecord>,
) -> Result<Rc<InstalledHostStateFactory>, NodeObservationServiceError> {
    if let Some(resolved) = resolved {
        return match record {
            Some(record) => {
                catalog.installed_capability_condition_factory_from_archive(resolved, record)
            }
            None => catalog.installed_capability_condition_factory(resolved),
        }
        .map_err(refused);
    }
    let scenario = NodeScenario::from_json(request.scenario.as_slice()).map_err(refused)?;
    match record {
        Some(record) => {
            catalog.host_state_factory_from_archive(&request.selections, &scenario, record)
        }
        None => catalog.host_state_factory(&request.selections, &scenario),
    }
    .map_err(refused)
}
