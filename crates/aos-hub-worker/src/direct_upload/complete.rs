//! Batched Complete boundaries and bounded independent physical publication.
//!
//! Each object retains its original intent before effects. Native receives one
//! request per logical boundary for the surviving objects, while reservations
//! and provider effects remain ordered within each object. Positive guard
//! receipts support commit retries without repeating settled provider effects.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;

use super::{
    batches::{bounded, item_error, merge_reply},
    control::LogicalReply,
};

#[cfg(test)]
mod tests;
#[cfg(target_arch = "wasm32")]
mod worker;

#[async_trait::async_trait(?Send)]
trait Runtime {
    fn maximum(&self) -> usize;
    fn fresh_context(&self, original: &DirectRequestContext) -> Result<DirectRequestContext>;
    async fn logical(
        &self,
        context: &DirectRequestContext,
        value: DirectUploadLogicalRequest,
    ) -> Result<LogicalReply>;
    async fn prepare(
        &self,
        context: &DirectRequestContext,
        admission: DirectUploadAdmission,
        complete: DirectCompleteRequest,
    ) -> Result<Option<Ready>>;
    async fn reserve(&self, context: &DirectRequestContext, ready: Ready) -> Result<Reserved>;
    async fn promote(&self, reserved: Reserved, permission: &LogicalReply) -> Result<Published>;
    async fn acknowledge(
        &self,
        item: &Published,
        committed: &LogicalReply,
        public_bytes: &[u8],
    ) -> Result<()>;
}

async fn fresh_logical<R: Runtime>(
    runtime: &R,
    context: &DirectRequestContext,
    value: DirectUploadLogicalRequest,
) -> Result<LogicalReply> {
    runtime
        .logical(&runtime.fresh_context(context)?, value)
        .await
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn execute(
    request: &::worker::Request,
    env: &::worker::Env,
    qualified: &super::config::QualifiedConfig,
    context: &DirectRequestContext,
    public_bytes: &[u8],
    items: Vec<DirectCompleteRequest>,
    response: &mut DirectUploadResponse,
) {
    run(
        &worker::WorkerRuntime {
            request,
            env,
            qualified: Some(qualified),
        },
        context,
        public_bytes,
        items,
        response,
    )
    .await;
}

/// Replays retained positive publication through the same authenticated scheduler.
#[cfg(target_arch = "wasm32")]
pub(super) async fn execute_historical(
    request: &::worker::Request,
    env: &::worker::Env,
    context: &DirectRequestContext,
    public_bytes: &[u8],
    items: Vec<DirectCompleteRequest>,
    response: &mut DirectUploadResponse,
) {
    run(
        &worker::WorkerRuntime {
            request,
            env,
            qualified: None,
        },
        context,
        public_bytes,
        items,
        response,
    )
    .await;
}

fn require_historical_original(
    admission: &DirectUploadAdmission,
    complete: &DirectCompleteRequest,
    retained_admission: &DirectUploadAdmission,
    retained_complete: Option<&DirectCompleteRequest>,
) -> Result<()> {
    ensure!(
        retained_admission == admission && retained_complete == Some(complete),
        "direct historical original differs"
    );
    Ok(())
}

fn require_historical_publication(ready: &Ready) -> Result<()> {
    ensure!(
        ready
            .admission
            .placements
            .iter()
            .all(|placement| ready.is_settled(placement.placement_id)),
        "direct historical publication incomplete"
    );
    Ok(())
}

struct Ready {
    admission: DirectUploadAdmission,
    complete: DirectCompleteRequest,
    stage: DirectVerifiedStageEvidence,
    settled: Vec<DirectSettledPlacement>,
}

impl Ready {
    fn authorization(&self) -> DirectSessionAuthorization {
        DirectSessionAuthorization {
            session: self.complete.session.clone(),
            operation_id: self.complete.operation_id.clone(),
            expected_resource_version: Some(self.complete.expected_resource_version),
            complete_intent: Some(self.complete.clone()),
        }
    }

    fn is_settled(&self, placement_id: WireInteger) -> bool {
        self.settled
            .iter()
            .any(|item| item.evidence.placement_id == placement_id)
    }
}

struct Reserved {
    ready: Ready,
    baselines: Vec<DirectDestinationBaselineEvidence>,
    witnesses: Vec<DirectDestinationBaselineWitness>,
}

struct Published {
    ready: Ready,
    evidence: DirectCompletionEvidence,
    guards: Vec<DirectFinalGuardRecord>,
}

async fn run<R: Runtime>(
    runtime: &R,
    context: &DirectRequestContext,
    public_bytes: &[u8],
    items: Vec<DirectCompleteRequest>,
    response: &mut DirectUploadResponse,
) {
    let sessions = items
        .iter()
        .map(|complete| DirectSessionAuthorization {
            session: complete.session.clone(),
            operation_id: complete.operation_id.clone(),
            expected_resource_version: Some(complete.expected_resource_version),
            complete_intent: Some(complete.clone()),
        })
        .collect();
    let freeze = DirectUploadLogicalRequest::Authorize {
        action: DirectLogicalAction::Complete,
        complete_step: Some(DirectCompleteStep::Freeze),
        stage_evidence: Vec::new(),
        retained_stage_digests: Vec::new(),
        baseline_evidence: Vec::new(),
        baseline_witnesses: Vec::new(),
        baseline_witness_refs: Vec::new(),
        settled_placements: Vec::new(),
        sessions,
    };
    let frozen = match fresh_logical(runtime, context, freeze).await {
        Ok(reply) => reply,
        Err(error) => {
            for item in &items {
                response.errors.push(item_error(&item.operation_id, &error));
            }
            return;
        }
    };
    let items = items
        .into_iter()
        .filter_map(|complete| {
            let expected = DirectSessionAuthorization {
                session: complete.session.clone(),
                operation_id: complete.operation_id.clone(),
                expected_resource_version: Some(complete.expected_resource_version),
                complete_intent: Some(complete.clone()),
            };
            if !frozen.reply.authorizations.contains(&expected) {
                missing_authorization(response, &complete, &frozen.reply);
                return None;
            }
            let admitted = frozen.reply.admissions.iter().find(|admission| {
                admission.session_id == complete.session.session_id
                    && admission.logical_fingerprint == complete.session.logical_fingerprint
            });
            if admitted.is_none() {
                missing_authorization(response, &complete, &frozen.reply);
            }
            admitted.map(|admission| (admission.clone(), complete))
        })
        .collect::<Vec<_>>();
    merge_reply(response, frozen.reply);

    let maximum = runtime.maximum();
    let prepared = bounded(
        items.into_iter().map(|(admission, complete)| async move {
            let identity = complete.operation_id.clone();
            (
                identity,
                runtime.prepare(context, admission, complete).await,
            )
        }),
        maximum,
    )
    .await;

    let mut pending = Vec::new();
    let mut published = Vec::new();
    for (identity, result) in prepared {
        match result {
            Ok(Some(ready)) if ready.settled.len() == ready.admission.placements.len() => {
                match finish(ready, context) {
                    Ok(item) => published.push(item),
                    Err(error) => response.errors.push(item_error(&identity, &error)),
                }
            }
            Ok(Some(ready)) => pending.push(ready),
            Ok(None) => {}
            Err(error) => response.errors.push(item_error(&identity, &error)),
        }
    }

    if !pending.is_empty() {
        let value = phase(
            &pending,
            DirectCompleteStep::Baseline,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match fresh_logical(runtime, context, value).await {
            Ok(reply) => {
                pending.retain(|item| {
                    let allowed = authorized(item, &reply.reply);
                    if !allowed {
                        missing_authorization(response, &item.complete, &reply.reply);
                    }
                    allowed
                });
                merge_reply(response, reply.reply);
            }
            Err(error) => {
                fail_ready(response, &pending, &error);
                pending.clear();
            }
        }
    }

    // Native checks that witnesses were observed after this phase was minted.
    // Retain the same nonce and issue time across reservation waits and transport.
    let promotion_context = match runtime.fresh_context(context) {
        Ok(value) => value,
        Err(error) => {
            fail_ready(response, &pending, &error);
            pending.clear();
            context.clone()
        }
    };
    let reservations = bounded(
        pending.into_iter().map(|ready| {
            let promotion_context = &promotion_context;
            async move {
                let identity = ready.complete.operation_id.clone();
                (identity, runtime.reserve(promotion_context, ready).await)
            }
        }),
        maximum,
    )
    .await;
    let mut reserved = Vec::new();
    for (identity, result) in reservations {
        match result {
            Ok(item) => reserved.push(item),
            Err(error) => response.errors.push(item_error(&identity, &error)),
        }
    }

    if !reserved.is_empty() {
        let permission = match promotion_request(&reserved) {
            Ok(value) => runtime.logical(&promotion_context, value).await,
            Err(error) => Err(error),
        };
        match permission {
            Ok(reply) => {
                reserved.retain(|item| {
                    let allowed = authorized(&item.ready, &reply.reply);
                    if !allowed {
                        missing_authorization(response, &item.ready.complete, &reply.reply);
                    }
                    allowed
                });
                let promoted = bounded(
                    reserved.into_iter().map(|item| {
                        let permission = &reply;
                        async move {
                            let identity = item.ready.complete.operation_id.clone();
                            (identity, runtime.promote(item, permission).await)
                        }
                    }),
                    maximum,
                )
                .await;
                merge_reply(response, reply.reply);
                for (identity, result) in promoted {
                    match result {
                        Ok(item) => published.push(item),
                        Err(error) => response.errors.push(item_error(&identity, &error)),
                    }
                }
            }
            Err(error) => {
                for item in &reserved {
                    response
                        .errors
                        .push(item_error(&item.ready.complete.operation_id, &error));
                }
            }
        }
    }

    if published.is_empty() {
        return;
    }

    let settlement = match commit_request(&published) {
        Ok(value) => fresh_logical(runtime, context, value).await,
        Err(error) => Err(error),
    };
    let committed = match settlement {
        Ok(reply) => reply,
        Err(error) => {
            for item in &published {
                response
                    .errors
                    .push(item_error(&item.ready.complete.operation_id, &error));
            }
            return;
        }
    };

    // A missing or refused commit acknowledgement leaves every physical owner
    // held. Only an exact signed committed status can release its guards.
    for item in &published {
        if !is_committed(item, &committed.reply) {
            missing_authorization(response, &item.ready.complete, &committed.reply);
        }
    }
    let acknowledged = bounded(
        published
            .iter()
            .filter(|item| is_committed(item, &committed.reply))
            .map(|item| async {
                let result = runtime.acknowledge(item, &committed, public_bytes).await;
                (&item.ready.complete.operation_id, result)
            }),
        maximum,
    )
    .await;
    merge_reply(response, committed.reply);
    for (identity, result) in acknowledged {
        if let Err(error) = result {
            response.errors.push(item_error(identity, &error));
        }
    }
}

fn phase(
    ready: &[Ready],
    step: DirectCompleteStep,
    baseline_evidence: Vec<DirectDestinationBaselineEvidence>,
    baseline_witnesses: Vec<DirectDestinationBaselineWitness>,
    settled_placements: Vec<DirectSettledPlacement>,
) -> DirectUploadLogicalRequest {
    DirectUploadLogicalRequest::Authorize {
        action: DirectLogicalAction::Complete,
        complete_step: Some(step),
        stage_evidence: ready.iter().map(|item| item.stage.clone()).collect(),
        retained_stage_digests: Vec::new(),
        baseline_evidence,
        baseline_witnesses,
        baseline_witness_refs: Vec::new(),
        settled_placements,
        sessions: ready.iter().map(Ready::authorization).collect(),
    }
}

fn promotion_request(reserved: &[Reserved]) -> Result<DirectUploadLogicalRequest> {
    // Native expands stage references from its retained Baseline originals.
    // Witness references commit to the exact supplied immutable binding; full
    // originals stay here for the guard's independent physical validation.
    Ok(DirectUploadLogicalRequest::Authorize {
        action: DirectLogicalAction::Complete,
        complete_step: Some(DirectCompleteStep::Promote),
        sessions: reserved
            .iter()
            .map(|item| item.ready.authorization())
            .collect(),
        stage_evidence: Vec::new(),
        retained_stage_digests: reserved
            .iter()
            .map(|item| DirectRetainedStageDigest::from_evidence(&item.ready.stage))
            .collect::<Result<Vec<_>>>()?,
        baseline_evidence: reserved
            .iter()
            .flat_map(|item| item.baselines.iter().cloned())
            .collect(),
        baseline_witnesses: Vec::new(),
        baseline_witness_refs: reserved
            .iter()
            .flat_map(|item| &item.witnesses)
            .map(DirectBaselineWitnessRef::from_witness)
            .collect::<Result<Vec<_>>>()?,
        settled_placements: reserved
            .iter()
            .flat_map(|item| item.ready.settled.iter().cloned())
            .collect(),
    })
}

fn authorized(ready: &Ready, reply: &DirectUploadLogicalReply) -> bool {
    // Freeze supplied and validated the immutable admission. Later boundaries
    // authenticate the same full Complete without repeating that snapshot.
    reply.authorizations.contains(&ready.authorization())
}

fn commit_request(published: &[Published]) -> Result<DirectUploadLogicalRequest> {
    Ok(DirectUploadLogicalRequest::Commit {
        evidence: published.iter().map(|item| item.evidence.clone()).collect(),
        final_guards: Vec::new(),
        final_guard_refs: published
            .iter()
            .flat_map(|item| &item.guards)
            .map(DirectFinalGuardRef::from_record)
            .collect::<Result<Vec<_>>>()?,
    })
}

fn finish(ready: Ready, context: &DirectRequestContext) -> Result<Published> {
    ensure!(
        ready.settled.len() == ready.admission.placements.len(),
        "direct publication placement set incomplete"
    );
    let mut placements = Vec::new();
    let mut guards = Vec::new();
    for placement in &ready.admission.placements {
        let settled = ready
            .settled
            .iter()
            .find(|item| item.evidence.placement_id == placement.placement_id)
            .ok_or_else(|| anyhow::anyhow!("direct publication placement absent"))?;
        placements.push(settled.evidence.clone());
        guards.push(settled.guard.clone());
    }

    let evidence = DirectCompletionEvidence {
        session_id: ready.admission.session_id.clone(),
        logical_fingerprint: ready.admission.logical_fingerprint.clone(),
        operation_id: ready.complete.operation_id.clone(),
        part_count: ready.stage.part_count,
        sha256: ready.stage.sha256.clone(),
        byte_size: ready.stage.byte_size,
        placements,
        projection: ready.stage.projection.clone(),
    };
    evidence.validate_against(&ready.admission, &context.deployment_id)?;
    Ok(Published {
        ready,
        evidence,
        guards,
    })
}

fn is_committed(item: &Published, reply: &DirectUploadLogicalReply) -> bool {
    reply.sessions.iter().any(|status| {
        status.session == item.ready.complete.session
            && status.intent == item.ready.admission.intent
            && status.state == DirectSessionState::Committed
            && status.resource_version.get() > item.ready.complete.expected_resource_version.get()
            && status.placements
                == item
                    .ready
                    .complete
                    .manifests
                    .iter()
                    .map(|value| value.placement.clone())
                    .collect::<Vec<_>>()
    })
}

fn fail_ready(response: &mut DirectUploadResponse, ready: &[Ready], error: &anyhow::Error) {
    for item in ready {
        response
            .errors
            .push(item_error(&item.complete.operation_id, error));
    }
}

fn missing_authorization(
    response: &mut DirectUploadResponse,
    complete: &DirectCompleteRequest,
    reply: &DirectUploadLogicalReply,
) {
    if !reply.errors.iter().any(|error| {
        error.item_id == complete.operation_id || error.item_id == complete.session.session_id
    }) {
        response.errors.push(DirectItemError {
            item_id: complete.operation_id.clone(),
            code: DirectItemErrorCode::Unavailable,
        });
    }
}
