//! Installed terminal dispatch and original report continuation on the owner thread.

use std::{
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use crucible::{
    node_contract::{
        BeginResult, NodeRuntime, OperationToken, PublicationStatus, TerminalResultPublisher,
    },
    node_state::{
        HostArchive, HostArchiveRecord, HostWorldRestoreDriver, RestorePublication, StateLimits,
        stage_restore,
    },
};
use crucible_campaign::ExecutionId;
use crucible_cas::content_store::{ImmutableBlobBackend, MutableRefBackend, RefName};
use crucible_node_contract::{Id, U64, canonical};

use crate::{
    node_control::{
        NodeControlError, execution_id, refused,
        terminal_state::{NodeTerminalStage, NodeTerminalStateRequest},
    },
    node_observed_executor::{
        InstalledNodeCatalog, InstalledNodeKind, StoredTerminalResultPublisher,
        StoredWorldActivationPublisher,
    },
    node_scenario::NodeScenario,
};

use super::{activation_reference, advance, capture_id, reclaim, requirements};

pub(super) fn execute(
    request: &NodeTerminalStateRequest,
    catalog: &mut InstalledNodeCatalog,
    archive: &HostArchive,
    limits: StateLimits,
    blobs: &Arc<dyn ImmutableBlobBackend>,
    refs: &Arc<dyn MutableRefBackend>,
) -> Result<HostArchiveRecord, NodeControlError> {
    request.validate()?;
    let (selections, scenario_bytes, stage, source, ceiling) = match request {
        NodeTerminalStateRequest::Capture {
            selections,
            scenario,
            stage,
            ceiling_ps,
            ..
        } => (selections, scenario, *stage, None, Some(*ceiling_ps)),
        NodeTerminalStateRequest::Restore {
            selections,
            scenario,
            source,
            stage,
            ..
        } => (selections, scenario, *stage, Some(source), None),
        NodeTerminalStateRequest::Status { .. } => {
            return Err(refused("terminal status grants no native authority"));
        }
    };
    let scenario = NodeScenario::from_json(scenario_bytes.as_slice()).map_err(refused)?;
    let mut activation_publisher = StoredWorldActivationPublisher::new(
        Arc::clone(blobs),
        Arc::clone(refs),
        activation_reference(request.execution())?,
    )
    .map_err(refused)?;
    let nonce = native_execution(request.execution())?;

    if let Some(source) = source {
        let record = archive.load(source).map_err(refused)?;
        let ordinal = record.manifest().event_ordinal;
        let factory = catalog
            .host_state_factory_from_archive(selections, &scenario, &record)
            .map_err(refused)?;
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
            .map_err(|_| refused("original terminal world restore staging was refused"))?;
        let RestorePublication::Committed(mut restored) =
            prepared.publish(&mut activation_publisher)
        else {
            return Err(refused(
                "original terminal restoration activation requires reconciliation",
            ));
        };
        let activation = restored.activation().clone();
        let saved = restored
            .runtime_mut()
            .terminal_checkpoint()
            .ok_or_else(|| refused("original archive has no selected terminal custody"))?
            .clone();
        let token = restored
            .runtime_mut()
            .recover(&saved.record.operation)
            .map_err(refused)?;
        retain_stage(restored.runtime_mut(), &token, stage, blobs, refs)?;
        let captured = archive
            .capture_terminal_world(
                &graph,
                restored.runtime_mut(),
                &activation,
                saved.record.cut,
                ordinal,
                capture_id(request.execution())?,
                requirements()?,
                factory.as_ref(),
                factory.as_ref(),
            )
            .map_err(refused)?;
        drop(restored);
        drop(driver);
        reclaim(catalog.custody());
        Ok(captured)
    } else {
        let ceiling = ceiling.ok_or_else(|| refused("new terminal execution lacks a ceiling"))?;
        let semantic_node = selections
            .iter()
            .find(|selection| matches!(selection.kind, InstalledNodeKind::HostSemantics { .. }))
            .ok_or_else(|| refused("terminal execution has no installed semantic owner"))?
            .node
            .clone();
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
            .map_err(|_| refused("actual terminal world admission was refused"))?;
        runtime.arm_all().map_err(refused)?;
        let activation = runtime
            .activate(&mut activation_publisher)
            .map_err(refused)?;
        let (_, ordinal) = advance(
            &mut runtime,
            &graph,
            &activation,
            request.execution(),
            ceiling,
            activation.record().boundary,
            U64::new(0),
        )?;
        // Execution reaching its ceiling supplies no finalization authority.
        // Only the actual complete live native/coordinator closure can do so.
        let barrier = runtime
            .terminal_barrier(
                &graph,
                &activation,
                &semantic_node,
                Id::new(format!("terminal/finalize/{}", request.execution()))?,
                1 << 20,
            )
            .map_err(refused)?;
        let cut = barrier.record().cut;
        let BeginResult::Accepted(token) = runtime
            .begin_terminal_assertions(barrier)
            .map_err(refused)?
        else {
            return Err(refused("original native terminal operation was refused"));
        };
        let Poll::Ready(Ok(_)) = runtime.poll(&token, &mut Context::from_waker(Waker::noop()))
        else {
            return Err(refused(
                "original native terminal result remains unresolved",
            ));
        };
        retain_stage(&mut runtime, &token, stage, blobs, refs)?;
        let captured = archive
            .capture_terminal_world(
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

fn retain_stage(
    runtime: &mut NodeRuntime,
    token: &OperationToken,
    stage: NodeTerminalStage,
    blobs: &Arc<dyn ImmutableBlobBackend>,
    refs: &Arc<dyn MutableRefBackend>,
) -> Result<(), NodeControlError> {
    let saved = runtime
        .terminal_checkpoint()
        .ok_or_else(|| refused("original terminal checkpoint is absent"))?
        .clone();
    let original_stage = if saved.acknowledged {
        NodeTerminalStage::Acknowledged
    } else if saved.publication
        == Some(crucible::node_contract::TerminalPublicationState::Committed)
    {
        NodeTerminalStage::Published
    } else if saved.publication.is_none() {
        NodeTerminalStage::Completed
    } else {
        return Err(refused("original terminal publication is uncertain"));
    };
    if stage < original_stage {
        return Err(refused(
            "terminal continuation cannot erase original publication or ACK",
        ));
    }
    if stage == NodeTerminalStage::Completed {
        return Ok(());
    }
    let root = canonical::json_hash(
        "crucible.terminal-result-root.v1",
        &serde_json::to_value(&saved.record.operation)
            .map_err(crucible_node_contract::ContractError::from)?,
    )?;
    let mut publisher = StoredTerminalResultPublisher::new(
        Arc::clone(blobs),
        Arc::clone(refs),
        RefName::new(format!("node-world-coordinators/terminal/{}", root.digest))
            .map_err(refused)?,
        1 << 20,
    )
    .map_err(refused)?;
    if original_stage >= NodeTerminalStage::Published {
        let barrier = crucible::node_scheduling::InputPayload {
            reference: saved.reference.clone(),
            bytes: canonical::canonical_json(
                &serde_json::to_value(&saved.record)
                    .map_err(crucible_node_contract::ContractError::from)?,
            )?,
        };
        let report = saved
            .report
            .as_ref()
            .ok_or_else(|| refused("published original report body is absent"))?;
        // Historical source publication does not prove durability in a changed
        // backing store. Require the same actual original roots before an ACK.
        if publisher.reconcile(&barrier, report) != PublicationStatus::Committed {
            return Err(refused(
                "original terminal report roots are not durably retained",
            ));
        }
    }
    let (status, commit) = runtime
        .publish_terminal_result(token, &mut publisher, 1 << 20)
        .map_err(refused)?;
    if status != PublicationStatus::Committed {
        return Err(refused(
            "original terminal result publication requires reconciliation",
        ));
    }
    if stage == NodeTerminalStage::Acknowledged {
        let commit =
            commit.ok_or_else(|| refused("original terminal publication has no ACK authority"))?;
        runtime
            .acknowledge_terminal_result(token, &commit)
            .map_err(refused)?;
    }
    Ok(())
}

fn native_execution(execution: &str) -> Result<ExecutionId, NodeControlError> {
    let original = execution_id(execution)?;
    let mut hasher = blake3::Hasher::new_derive_key("crucible.terminal-state-execution.v1");
    hasher.update(&original.as_bytes());
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    ExecutionId::from_bytes(nonce).map_err(refused)
}
