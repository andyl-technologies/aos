//! Executes the installed native preservation points with original runtime tokens.
//!
//! Pending and held-publication cuts use the original coordinator boundary.
//! They do not advance an unrelated clock or manufacture a coherent horizon.
//! Cold completion recovers the saved grant and commits its original receipt;
//! it never admits a replacement RUN or replays an original publication.

use std::{
    collections::BTreeSet,
    path::PathBuf,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use crucible::{
    node_contract::{
        BeginResult, NodeRuntime, OperationOutcome, OperationToken, SavedRuntimeActivation,
    },
    node_state::{
        NativeArchive, NativeArchiveLimits, NativeWorldRestoreDriver, PublicationKnowledge,
        RestorePublication, StateLimits, StateRequirements, StateRestoreMode, stage_restore,
    },
};
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefCasOutcome,
    RefName,
};
use crucible_node_contract::{Bytes, Id, U64, canonical};

use super::super::{NodeObservedError, StoredWorldActivationPublisher, refused};
use super::{
    control::{NativeCapturePoint, NativeWorldOutcome, NativeWorldRequest},
    factory::MixedNativeFactory,
    installed::InstalledMixedEngine,
    publication::NativeCustodyPublisher,
};
use crate::supervision::ProcessDeadline;

pub(super) struct ExecutedNativeWorld {
    pub(super) outcome: NativeWorldOutcome,
    pub(super) target: crucible::node_contract::ActivationRecord,
    pub(super) namespace: PathBuf,
}

pub(super) fn execute(
    request: &NativeWorldRequest,
    engine: &InstalledMixedEngine,
    archive: &NativeArchive,
    blobs: &Arc<dyn ImmutableBlobBackend>,
    refs: &Arc<dyn MutableRefBackend>,
) -> Result<ExecutedNativeWorld, NodeObservedError> {
    request.validate()?;
    let stored = StoredWorldActivationPublisher::new(
        blobs.clone(),
        refs.clone(),
        RefName::new(format!(
            "node-world-activations/native-{}",
            request.execution()
        ))
        .map_err(error)?,
    )
    .map_err(error)?;
    let mut publisher = NativeCustodyPublisher {
        restored: None,
        stored,
        queue: engine.native.clone(),
    };

    match request {
        NativeWorldRequest::Capture {
            execution,
            isa,
            point,
        } => {
            let live = engine.prepare_live(isa.name())?;
            let graph = live.graph.clone();
            let target = live.target.clone();
            let namespace = live.namespace.clone();
            let factory = Rc::new(MixedNativeFactory::for_live(&live, engine.native.clone()));
            let mut runtime = live
                .realization
                .admit(&graph)
                .map_err(|failure| error(&failure.error))?;
            runtime.arm_all().map_err(error)?;
            // This installed backend edition uses legacy native preparation.
            // Its whole-world activation remains version one; the signed archive
            // separately binds the complete native/runtime/coordinator custody.
            let activation = runtime.activate(&mut publisher).map_err(error)?;
            engine
                .native
                .record_publication(&target, PublicationKnowledge::Committed)
                .map_err(error)?;

            for node in graph.node_ids() {
                let observation = runtime
                    .observe_scheduling(&activation, node)
                    .map_err(error)?;
                runtime
                    .scheduler(&graph, &activation)
                    .map_err(error)?
                    .accept_boundary_observation(observation)
                    .map_err(error)?;
            }
            let operation = Id::new(format!("native/{execution}/original"))?;
            let admission = runtime
                .scheduler(&graph, &activation)
                .map_err(error)?
                .admit_exact(&Id::new("cpu")?, operation.clone(), U64::new(1_000_000_000))
                .map_err(error)?;
            let BeginResult::Accepted(token) = runtime.begin_admitted(admission).map_err(error)?
            else {
                return Err(refused("installed native original grant was refused"));
            };
            let mut context = Context::from_waker(Waker::noop());
            if !runtime.poll(&token, &mut context).is_pending() {
                return Err(refused(
                    "installed native first original prefix was not pending",
                ));
            }
            if *point == NativeCapturePoint::HeldPublication {
                finish_original(&mut runtime, &token)?;
            }

            let ordinal = U64::new(17);
            let record = archive
                .capture_world(
                    &graph,
                    &mut runtime,
                    &activation,
                    target.boundary,
                    ordinal,
                    Id::new(format!("native/{execution}/capture"))?,
                    requirements()?,
                    &factory.immutable(),
                    factory.as_ref(),
                )
                .map_err(error)?;
            let original = record
                .runtime_snapshot()
                .map_err(error)?
                .operations
                .into_iter()
                .find(|saved| saved.operation == operation)
                .ok_or_else(|| refused("signed native original operation is absent"))?;

            Ok(ExecutedNativeWorld {
                target,
                namespace,
                outcome: NativeWorldOutcome::Completed {
                    artifact: record.artifact().clone(),
                    manifest: Box::new(record.manifest().clone()),
                    activation: Box::new(SavedRuntimeActivation::from(activation.record())),
                    original: Box::new(original),
                    completion_evidence: None,
                },
            })
        }
        NativeWorldRequest::Restore {
            isa,
            source,
            complete_original,
            ..
        } => {
            let record = archive.load(source).map_err(error)?;
            let saved = record.runtime_snapshot().map_err(error)?;
            if saved.operations.len() != 1 {
                return Err(refused(
                    "installed native source must retain one original grant",
                ));
            }
            let original = saved.operations[0].operation.clone();
            let plan = engine.prepare_cold(record.clone(), isa.name())?;
            if plan.profile.public_continuation {
                publisher = NativeCustodyPublisher::for_public_restore(
                    publisher.stored,
                    engine.native.clone(),
                    &record,
                    &plan.target,
                )?;
            }
            let graph = plan.graph.clone();
            let target = plan.target.clone();
            let namespace = plan.namespace.clone();
            let factory = Rc::new(MixedNativeFactory::for_cold(plan, engine.native.clone()));
            let verified = record
                .admit(&graph, requirements()?, factory.as_ref())
                .map_err(error)?;
            let mut driver = NativeWorldRestoreDriver::new(
                graph.clone(),
                record.clone(),
                factory,
                engine.runtime.clone(),
            )
            .map_err(error)?;
            let prepared = stage_restore(
                &graph,
                verified,
                target.clone(),
                &mut driver,
                archive_limits().state,
            )
            .map_err(|failure| error(&failure.error))?;
            let RestorePublication::Committed(mut restored) = prepared.publish(&mut publisher)
            else {
                return Err(refused(
                    "installed native restoration publication is uncertain",
                ));
            };
            engine
                .native
                .record_publication(&target, PublicationKnowledge::Committed)
                .map_err(error)?;

            let completion_evidence = if *complete_original {
                let activation = SavedRuntimeActivation::from(restored.activation().record());
                let runtime = restored.runtime_mut();
                let token = runtime.recover(&original).map_err(error)?;
                let outcome = finish_original(runtime, &token)?;
                let evidence = retain_completion(
                    runtime,
                    &token,
                    &outcome,
                    &activation,
                    request.execution(),
                    blobs,
                    refs,
                )?;
                let commit = if saved.operations[0].scheduling_commit.is_some() {
                    runtime.recover_scheduling_commit(&token).map_err(error)?
                } else {
                    let receipt = runtime.scheduling_receipt(&token).map_err(error)?;
                    runtime.commit_scheduling_receipt(receipt).map_err(error)?
                };
                runtime
                    .acknowledge_scheduled(&token, &commit)
                    .map_err(error)?;
                Some(evidence.encode())
            } else {
                None
            };
            let activation = SavedRuntimeActivation::from(restored.activation().record());
            let actual = restored
                .runtime_mut()
                .runtime_snapshot(saved.capture_cut, saved.capture_ordinal, 16 * 1024 * 1024)
                .map_err(error)?
                .operations
                .into_iter()
                .find(|entry| entry.operation == original)
                .ok_or_else(|| refused("fresh native original ledger is absent"))?;

            Ok(ExecutedNativeWorld {
                target,
                namespace,
                outcome: NativeWorldOutcome::Completed {
                    artifact: record.artifact().clone(),
                    manifest: Box::new(record.manifest().clone()),
                    activation: Box::new(activation),
                    original: Box::new(actual),
                    completion_evidence,
                },
            })
        }
        NativeWorldRequest::Status { .. } => {
            Err(refused("native status cannot dispatch execution"))
        }
    }
}

fn finish_original(
    runtime: &mut NodeRuntime,
    token: &OperationToken,
) -> Result<OperationOutcome, NodeObservedError> {
    let deadline = ProcessDeadline::after(Duration::from_secs(180))
        .ok_or_else(|| refused("native operational deadline is unrepresentable"))?;
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..4096 {
        match runtime.poll(token, &mut context) {
            Poll::Ready(outcome) => return outcome.map_err(error),
            Poll::Pending if !deadline.expired() => deadline.pause(Duration::from_millis(1)),
            Poll::Pending => break,
        }
    }
    Err(refused(
        "original native operation exceeded installed operational poll deadline",
    ))
}

fn retain_completion(
    runtime: &mut NodeRuntime,
    token: &OperationToken,
    outcome: &OperationOutcome,
    activation: &SavedRuntimeActivation,
    execution: &str,
    blobs: &Arc<dyn ImmutableBlobBackend>,
    refs: &Arc<dyn MutableRefBackend>,
) -> Result<ContentId, NodeObservedError> {
    let observation = outcome
        .scheduling
        .as_ref()
        .ok_or_else(|| refused("original native completion lacks scheduling evidence"))?;
    let mut references = BTreeSet::from([observation.proof_ref.clone()]);
    references.extend(
        observation
            .bounds
            .iter()
            .map(|bound| bound.proof_ref.clone()),
    );
    references.extend(
        observation
            .publications
            .iter()
            .map(|publication| publication.payload.clone()),
    );
    let references: Vec<_> = references.into_iter().collect();
    let objects = runtime
        .operation_evidence(token, &references, U64::new(16 * 1024 * 1024))
        .map_err(error)?;
    let objects: Vec<_> = objects
        .into_iter()
        .map(|object| {
            serde_json::json!({
                "reference": object.reference, "bytes": Bytes::new(object.bytes),
            })
        })
        .collect();
    let bytes = canonical::canonical_json(&serde_json::json!({
        "format":"crucible.native-world-completion-evidence", "version":1,
        "activation":activation, "operation":token.operation(), "objects":objects,
    }))?;
    if bytes.len() > 24 * 1024 * 1024 {
        return Err(refused(
            "original native completion evidence exceeds its finite ceiling",
        ));
    }
    let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    let _guard = refs.acquire_publication_guard().map_err(error)?;
    let receipt = blobs
        .put_if_absent(identity, &BlobHandle::from_bytes(bytes))
        .map_err(error)?;
    if !receipt.is_durable() {
        return Err(refused(
            "original native completion evidence is not durable",
        ));
    }
    let reference = super::ledger::evidence_ref(execution)?;
    match refs
        .compare_exchange(&reference, None, identity)
        .map_err(error)?
    {
        RefCasOutcome::Advanced { next } if next == identity => Ok(identity),
        RefCasOutcome::Conflict {
            current: Some(current),
            ..
        } if current == identity => Ok(identity),
        _ => Err(refused(
            "original native completion evidence requires reconciliation before ACK",
        )),
    }
}

pub(super) fn archive_limits() -> NativeArchiveLimits {
    NativeArchiveLimits {
        state: StateLimits {
            maximum_content_bytes: 512 * 1024 * 1024,
            maximum_total_content_bytes: 2 * 1024 * 1024 * 1024,
            maximum_record_bytes: 16 * 1024 * 1024,
            maximum_native_processes: 8192,
            ..StateLimits::default()
        },
        native: crucible::node_contract::NativeCaptureLimits {
            maximum_objects: 20_000,
            maximum_record_bytes: 16 * 1024 * 1024,
            maximum_total_record_bytes: 64 * 1024 * 1024,
            maximum_artifact_bytes: 2 * 1024 * 1024 * 1024,
            maximum_total_artifact_bytes: 8 * 1024 * 1024 * 1024,
        },
    }
}

fn requirements() -> Result<StateRequirements, NodeObservedError> {
    Ok(StateRequirements {
        preservation_contract: Id::new("mixed/native-preservation-v1")?,
        exact_model_continuation: true,
        deterministic: true,
        restore_mode: StateRestoreMode::DurableRestart,
    })
}

fn error(error: impl std::fmt::Display) -> NodeObservedError {
    refused(&error.to_string())
}
