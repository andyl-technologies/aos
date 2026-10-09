//! Runs genuine planner cuts beneath the selected standalone Clock archive policy.

use super::{
    ActorStorage, CapabilityPreparationAction, CapabilityPreparationRequest,
    CapabilityPreparationState, NodeObservationServiceError, encode, execution_id, refused,
};
use crate::{
    node_execution::{ExactOperationNames, ExactOperationRequest, plan_exact_operation},
    node_observed_executor::{
        InstalledNodeCatalog, ResolvedCapabilityWorld, StoredWorldActivationPublisher,
    },
    node_scenario::NodeRunConfiguration,
};
use crucible::{
    node_admission::AdmittedGraph,
    node_contract::{BeginResult, NodeRuntime, OperationOutcome, WorldActivation},
    node_state::{
        NativeArchive, NativeArchiveLimits, NativeWorldRestoreDriver, RestorePublication,
        StateRequirements, StateRestoreMode, stage_restore,
    },
};
use crucible_cas::content_store::RefName;
use crucible_node_contract::{Bytes, Id, Phase, Position, U64, canonical};
use std::{
    rc::Rc,
    task::{Context, Poll, Waker},
};

fn requirements() -> Result<StateRequirements, NodeObservationServiceError> {
    Ok(StateRequirements {
        preservation_contract: Id::new("host/preservation-v1").map_err(refused)?,
        exact_model_continuation: true,
        deterministic: true,
        restore_mode: StateRestoreMode::DurableRestart,
    })
}

fn limits() -> NativeArchiveLimits {
    let mut limits = NativeArchiveLimits::default();
    // The measured source-built CLI may retain debug information. Its
    // immutable executable remains one independently authenticated object;
    // this fixed allowance does not alter native record or closure ceilings.
    limits.state.maximum_content_bytes = 256 * 1024 * 1024;
    limits
}

fn publisher(
    storage: &ActorStorage,
    execution: &str,
) -> Result<StoredWorldActivationPublisher, NodeObservationServiceError> {
    StoredWorldActivationPublisher::new(
        storage.blobs.clone(),
        storage.refs.clone(),
        RefName::new(format!("node-world-activations/capability-{execution}")).map_err(refused)?,
    )
    .map_err(refused)
}

fn advance(
    runtime: &mut NodeRuntime,
    graph: &AdmittedGraph,
    activation: &WorldActivation,
    execution: &str,
    horizon: U64,
) -> Result<OperationOutcome, NodeObservationServiceError> {
    let node = graph
        .node_ids()
        .next()
        .ok_or_else(|| refused("installed Clock node absent"))?;
    let observed = runtime
        .observe_scheduling(activation, node)
        .map_err(refused)?;
    runtime
        .scheduler(graph, activation)
        .map_err(refused)?
        .accept_boundary_observation(observed)
        .map_err(refused)?;
    let operation = Id::new(format!("capability/{execution}/advance")).map_err(refused)?;
    let grant = plan_exact_operation::<crate::node_observed_executor::NodeObservedError, _>(
        runtime,
        ExactOperationRequest {
            graph,
            activation,
            node,
            horizon,
            names: ExactOperationNames {
                operation,
                stage: Id::new(format!("capability/{execution}/stage")).map_err(refused)?,
                batch: Id::new(format!("capability/{execution}/batch")).map_err(refused)?,
            },
        },
        |_| Ok(()),
    )
    .map_err(refused)?
    .ok_or_else(|| refused("actual Clock planner has no safe grant"))?;
    let BeginResult::Accepted(token) = runtime.begin_admitted(grant).map_err(refused)? else {
        return Err(refused(
            "actual native Clock refused original planner grant",
        ));
    };
    let Poll::Ready(result) = runtime.poll(&token, &mut Context::from_waker(Waker::noop())) else {
        // The selected synchronous Clock implementation never yields. Its
        // original token stays runtime-owned on refusal, then transfers to the
        // already reserved custody queue when this owning wrapper is dropped.
        return Err(refused("installed synchronous Clock did not complete"));
    };
    let outcome = result.map_err(refused)?;
    let receipt = runtime.scheduling_receipt(&token).map_err(refused)?;
    let commit = runtime
        .commit_scheduling_receipt(receipt)
        .map_err(refused)?;
    runtime
        .acknowledge_scheduled(&token, &commit)
        .map_err(refused)?;
    if outcome.scheduling.as_ref().is_none_or(|value| {
        value.reached != Position::new(horizon, 0.into(), Phase::BoundaryControl)
    }) {
        return Err(refused("actual Clock did not reach original planner cut"));
    }
    Ok(outcome)
}

pub(super) fn execute(
    request: CapabilityPreparationRequest,
    catalog: &mut InstalledNodeCatalog,
    resolved: ResolvedCapabilityWorld,
    configuration: NodeRunConfiguration,
    storage: &ActorStorage,
) -> Result<CapabilityPreparationState, NodeObservationServiceError> {
    // The installed factory conjunctively refuses non-Clock, unqualified
    // preservation, EXT or another owner's codec before any native allocation.
    let factory = catalog
        .installed_capability_clock_factory(&resolved)
        .map_err(refused)?;
    let archive = NativeArchive::open(&storage.capability_archive, limits()).map_err(refused)?;
    let scenario = Bytes::new(resolved.scenario().canonical_bytes().map_err(refused)?);
    let execution = execution_id(&request.execution)?;
    let cut = Position::new(configuration.horizon_ps, 0.into(), Phase::BoundaryControl);
    let name = Id::new(format!("capability/{}/capture", request.execution)).map_err(refused)?;
    let (artifact, progress) = match request.action {
        CapabilityPreparationAction::Capture {} => {
            let prepared = catalog
                .prepare_capability_world(&resolved, execution)
                .map_err(refused)?;
            let graph = prepared.graph;
            let mut runtime = prepared
                .realization
                .admit(&graph)
                .map_err(|failure| refused(&failure.error))?;
            runtime.arm_all().map_err(refused)?;
            let activation = runtime
                .activate(&mut publisher(storage, &request.execution)?)
                .map_err(refused)?;
            let outcome = advance(
                &mut runtime,
                &graph,
                &activation,
                &request.execution,
                configuration.horizon_ps,
            )?;
            let record = archive
                .capture_world_typed(
                    &graph,
                    &mut runtime,
                    &activation,
                    cut,
                    1.into(),
                    name,
                    requirements()?,
                    factory.as_ref(),
                    factory.as_ref(),
                )
                .map_err(refused)?;
            (record.artifact().clone(), Bytes::new(encode(&outcome)?))
        }
        CapabilityPreparationAction::Continue { source } => {
            let record = archive.load(&source).map_err(refused)?;
            if configuration.horizon_ps <= record.manifest().cut.time_ps {
                return Err(refused(
                    "future Clock horizon must follow unchanged original cut",
                ));
            }
            let (prepared, target) = catalog
                .prepare_capability_clock_restore(&resolved, execution, &record)
                .map_err(refused)?;
            let graph = Rc::new(prepared.graph);
            // This intentionally prepared target is closed and already owns its
            // native retirement slot. It grants no restore authority; the real
            // restore allocates under its separately reserved owning capsule.
            drop(prepared.realization);
            let _ = catalog
                .custody()
                .clone()
                .poll_reclamation(&mut Context::from_waker(Waker::noop()));
            let verified = record
                .admit(&graph, requirements()?, factory.as_ref())
                .map_err(refused)?;
            let mut driver = NativeWorldRestoreDriver::new(
                graph.clone(),
                record,
                factory.clone(),
                catalog.custody().clone(),
            )
            .map_err(refused)?;
            let staged = stage_restore(&graph, verified, target, &mut driver, limits().state)
                .map_err(|failure| refused(&failure.error))?;
            let RestorePublication::Committed(mut world) =
                staged.publish(&mut publisher(storage, &request.execution)?)
            else {
                return Err(refused("fresh complete Clock publication did not commit"));
            };
            let activation = world.activation().clone();
            let outcome = advance(
                world.runtime_mut(),
                &graph,
                &activation,
                &request.execution,
                configuration.horizon_ps,
            )?;
            let record = archive
                .capture_world_typed(
                    &graph,
                    world.runtime_mut(),
                    &activation,
                    cut,
                    2.into(),
                    name,
                    requirements()?,
                    factory.as_ref(),
                    factory.as_ref(),
                )
                .map_err(refused)?;
            (record.artifact().clone(), Bytes::new(encode(&outcome)?))
        }
        CapabilityPreparationAction::Observe {} => {
            return Err(refused(
                "ordinary observation does not select native capture",
            ));
        }
    };
    // Authenticated signed archive bytes are independently retained by the
    // installed archive. The receipt exposes identities, never restore grants.
    let _ = canonical::parse_json(progress.as_slice(), 1024 * 1024).map_err(refused)?;
    Ok(CapabilityPreparationState::Native {
        scenario,
        artifact,
        progress,
    })
}
