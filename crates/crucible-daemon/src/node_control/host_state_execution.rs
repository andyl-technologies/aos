//! Actual installed exact execution, authenticated restore, and unchanged-cut capture.

#[path = "host_state_advance.rs"]
mod host_state_advance;
#[path = "terminal_state_execution.rs"]
mod terminal_state_execution;

use std::{
    rc::Rc,
    sync::Arc,
    task::{Context, Waker},
    thread,
    time::Duration,
};

use crucible::{
    node_contract::RuntimeCustodyQueue,
    node_state::{
        HostArchive, HostArchiveRecord, HostWorldRestoreDriver, RestorePublication, StateLimits,
        StateRequirements, StateRestoreMode, stage_restore,
    },
};
use crucible_campaign::ExecutionId;
use crucible_cas::content_store::{ImmutableBlobBackend, MutableRefBackend};
use crucible_node_contract::{Id, U64};

use crate::{
    node_observed_executor::{InstalledNodeCatalog, StoredWorldActivationPublisher},
    node_scenario::NodeScenario,
};

use super::super::{
    NodeControlError, execution_id,
    host_state::{NodeHostStateRequest, activation_reference},
    refused,
};

use host_state_advance::advance;

pub(super) fn execute(
    request: &NodeHostStateRequest,
    catalog: &mut InstalledNodeCatalog,
    archive: &HostArchive,
    limits: StateLimits,
    blobs: &Arc<dyn ImmutableBlobBackend>,
    refs: &Arc<dyn MutableRefBackend>,
) -> Result<HostArchiveRecord, NodeControlError> {
    request.validate()?;
    if let NodeHostStateRequest::Terminal { request } = request {
        return terminal_state_execution::execute(request, catalog, archive, limits, blobs, refs);
    }
    let (selections, scenario, horizon, source) = match request {
        NodeHostStateRequest::Capture {
            selections,
            scenario,
            horizon_ps,
            ..
        } => (selections, scenario, *horizon_ps, None),
        NodeHostStateRequest::Restore {
            selections,
            scenario,
            horizon_ps,
            source,
            ..
        } => (selections, scenario, *horizon_ps, Some(source)),
        NodeHostStateRequest::Status { .. } => {
            return Err(refused("status grants no native state authority"));
        }
        NodeHostStateRequest::Terminal { .. } => {
            return Err(refused("terminal request uses its selected executor"));
        }
    };
    let scenario = NodeScenario::from_json(scenario.as_slice()).map_err(refused)?;
    let mut publisher = StoredWorldActivationPublisher::new(
        Arc::clone(blobs),
        Arc::clone(refs),
        activation_reference(request.execution())?,
    )
    .map_err(refused)?;
    let nonce = native_execution(request.execution())?;

    if let Some(source) = source {
        let record = archive.load(source).map_err(refused)?;
        let factory = catalog
            .host_state_factory_from_archive(selections, &scenario, &record)
            .map_err(refused)?;
        if horizon.get() < record.manifest().cut.time_ps.get() {
            return Err(refused(
                "restoration cannot rewind the original unchanged cut",
            ));
        }
        let source_ordinal = record.manifest().event_ordinal;
        let (graph, target) = catalog
            .prepare_host_restore_graph(selections, &scenario, &record, nonce)
            .map_err(refused)?;
        reclaim(catalog.custody());
        let graph = Rc::new(graph);
        let verified = record
            .admit(&graph, requirements()?, factory.as_ref(), limits)
            .map_err(refused)?;
        let mut driver = HostWorldRestoreDriver::new(
            Rc::clone(&graph),
            record,
            factory.clone(),
            catalog.custody().clone(),
        )
        .map_err(refused)?;
        let prepared = stage_restore(&graph, verified, target, &mut driver, limits)
            .map_err(|_| refused("actual whole-world restore staging was refused"))?;
        let RestorePublication::Committed(mut restored) = prepared.publish(&mut publisher) else {
            return Err(refused(
                "original restore activation requires reconciliation",
            ));
        };
        let activation = restored.activation().clone();
        let original_cut = activation.record().boundary;
        let (cut, ordinal) = advance(
            restored.runtime_mut(),
            &graph,
            &activation,
            request.execution(),
            horizon,
            original_cut,
            source_ordinal,
        )?;
        let captured = archive
            .capture_world(
                &graph,
                restored.runtime_mut(),
                &activation,
                cut,
                ordinal,
                capture_id(request.execution())?,
                requirements()?,
                factory.as_ref(),
                factory.as_ref(),
            )
            .map_err(refused)?;
        drop(restored);
        reclaim(catalog.custody());
        Ok(captured)
    } else {
        let factory = catalog
            .host_state_factory(selections, &scenario)
            .map_err(refused)?;
        let prepared = catalog
            .prepare_world(selections, scenario, nonce)
            .map_err(refused)?;
        let graph = prepared.graph;
        let mut runtime = prepared
            .realization
            .admit(&graph)
            .map_err(|_| refused("actual exact host world admission was refused"))?;
        runtime.arm_all().map_err(refused)?;
        let activation = runtime.activate(&mut publisher).map_err(refused)?;
        let (cut, ordinal) = advance(
            &mut runtime,
            &graph,
            &activation,
            request.execution(),
            horizon,
            activation.record().boundary,
            U64::new(0),
        )?;
        let captured = archive
            .capture_world(
                &graph,
                &mut runtime,
                &activation,
                cut,
                ordinal,
                capture_id(request.execution())?,
                requirements()?,
                factory.as_ref(),
                factory.as_ref(),
            )
            .map_err(refused)?;
        drop(runtime);
        reclaim(catalog.custody());
        Ok(captured)
    }
}

fn reclaim(queue: &RuntimeCustodyQueue) {
    while queue.reserved_worlds() != 0 {
        let mut context = Context::from_waker(Waker::noop());
        let _ = queue.clone().poll_reclamation(&mut context);
        if queue.reserved_worlds() != 0 {
            thread::sleep(Duration::from_millis(1));
        }
    }
}

fn requirements() -> Result<StateRequirements, NodeControlError> {
    Ok(StateRequirements {
        preservation_contract: Id::new("host/preservation-v1")?,
        exact_model_continuation: true,
        deterministic: true,
        restore_mode: StateRestoreMode::DurableRestart,
    })
}

fn native_execution(execution: &str) -> Result<ExecutionId, NodeControlError> {
    let original = execution_id(execution)?;
    let mut hasher = blake3::Hasher::new_derive_key("crucible.host-state-execution.v1");
    hasher.update(&original.as_bytes());
    let digest = hasher.finalize();
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&digest.as_bytes()[..16]);
    if nonce == [0; 16] {
        return Err(refused("state native nonce is invalid"));
    }
    ExecutionId::from_bytes(nonce).map_err(refused)
}

fn capture_id(execution: &str) -> Result<Id, NodeControlError> {
    Id::new(format!("capture/host-state/{execution}")).map_err(NodeControlError::from)
}

#[cfg(test)]
#[path = "host_state_execution_tests.rs"]
mod tests;
