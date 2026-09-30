//! Separate bounded durable verification queues for content and semantic metadata.
//!
//! Queue messages name the original immutable admission and Complete. Every
//! source follows a positive provider close and each result is durably retained
//! before acknowledgement. Queue redelivery may retry an exact immutable read;
//! it cannot redispatch a mutation or renew the logical owner.

use std::{cell::Cell, rc::Rc};

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;
use aos_hub_core::storage_authority::external_object::stage::{
    ExternalStageOperation, ExternalStageOutcome, ExternalStageResult,
};
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use worker::{Env, MessageExt as _};

use super::{
    config::QualifiedConfig,
    journal, managed, observation,
    storage::{self, Operation, Reply},
};

pub(crate) const BULK_QUEUE: &str = "HUB_DIRECT_VERIFY_BULK";
pub(crate) const METADATA_QUEUE: &str = "HUB_DIRECT_VERIFY_METADATA";

thread_local! {
    static BULK_ACTIVE: Rc<Cell<u32>> = Rc::new(Cell::new(0));
    static METADATA_ACTIVE: Rc<Cell<u32>> = Rc::new(Cell::new(0));
    static OBJECT_ACTIVE: Rc<Cell<u32>> = Rc::new(Cell::new(0));
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ClosedStage {
    Managed { object: managed::ObjectReceipt },
    External { result: ExternalStageResult },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CreatedStage {
    Managed { receipt: managed::CreateReceipt },
    External { result: ExternalStageResult },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerifiedPlacement {
    pub(crate) placement: DirectStagePlacementEvidence,
    pub(crate) closed: ClosedStage,
    pub(crate) external_verified: Option<ExternalStageResult>,
    pub(crate) sha256: String,
    pub(crate) byte_size: WireInteger,
    pub(crate) projection: Option<aos_hub_core::hybrid_ingress::HybridObjectProjection>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VerificationJob {
    pub(crate) version: u32,
    pub(crate) admission: DirectUploadAdmission,
    pub(crate) complete: DirectCompleteRequest,
    pub(crate) placement_id: WireInteger,
    pub(crate) closed: ClosedStage,
}

fn observation_object(job: &VerificationJob) -> observation::Object {
    let operation = step_id(
        &job.admission,
        job.placement_id,
        &job.complete.operation_id,
        "verify-stage",
    )
    .ok();
    let mut observed = observation::Object::new(
        &job.admission.session_id,
        &job.admission.logical_fingerprint,
        &job.admission.intent,
        job.placement_id,
        &job.complete.operation_id,
    );
    observed.operation_digest = operation.as_deref().map(observation::digest);
    observed.complete_operation_digest = Some(observation::digest(&job.complete.operation_id));
    observed
}

pub(crate) fn step_id(
    admission: &DirectUploadAdmission,
    placement_id: WireInteger,
    complete_operation: &str,
    step: &str,
) -> Result<String> {
    journal::digest(&(
        &admission.session_id,
        &admission.logical_fingerprint,
        placement_id,
        complete_operation,
        step,
    ))
}

pub(crate) async fn load_parts(
    env: &Env,
    admission: &DirectUploadAdmission,
    placement_id: WireInteger,
    manifest: Option<&DirectManifestCommitment>,
) -> Result<Vec<DirectManifestPart>> {
    let count = admission.intent.part_count()?;
    let mut parts = Vec::with_capacity(count as usize);
    let mut after = 0;
    while after < count {
        let Reply::Parts { parts: page } = storage::call(
            env,
            admission,
            Operation::PartPage {
                placement_id,
                after,
                maximum: 32,
            },
        )
        .await?
        else {
            anyhow::bail!("direct frozen part page differs");
        };
        let amount = (count - after).min(32);
        ensure!(
            page.len() == amount as usize,
            "direct frozen manifest incomplete"
        );
        for part in page {
            let observed = part
                .observed
                .ok_or_else(|| anyhow::anyhow!("direct frozen report absent"))?;
            ensure!(
                observed.part.part_number == after + 1,
                "direct frozen manifest unordered"
            );
            observed.part.validate(&admission.intent)?;
            parts.push(observed);
            after += 1;
        }
    }
    if let Some(manifest) = manifest {
        ensure!(
            manifest.part_count == count
                && canonical_manifest_digest(&admission.intent, &manifest.placement, &parts)?
                    == manifest.manifest_digest,
            "direct retained complete manifest differs"
        );
    }
    Ok(parts)
}

pub(crate) async fn close(
    env: &Env,
    admission: &DirectUploadAdmission,
    complete: &DirectCompleteRequest,
    placement_id: WireInteger,
    created: &CreatedStage,
) -> Result<ClosedStage> {
    close_checked(
        env,
        admission,
        complete,
        placement_id,
        created,
        admission.expires_at,
        || Ok(()),
    )
    .await
}

pub(crate) async fn close_checked<F: Fn() -> Result<()>>(
    env: &Env,
    admission: &DirectUploadAdmission,
    complete: &DirectCompleteRequest,
    placement_id: WireInteger,
    created: &CreatedStage,
    expires_at: WireInteger,
    before_dispatch: F,
) -> Result<ClosedStage> {
    let placement = storage::placement(admission, placement_id)?;
    let manifest = complete
        .manifests
        .iter()
        .find(|item| item.placement.placement_id == placement_id)
        .ok_or_else(|| anyhow::anyhow!("direct complete destination absent"))?;
    let parts = load_parts(env, admission, placement_id, Some(manifest)).await?;
    let key = direct_staging_key(&admission.session_id, placement)?;
    let operation_id = step_id(
        admission,
        placement_id,
        &complete.operation_id,
        "close-stage",
    )?;
    match (&placement.physical, created) {
        (
            DirectPhysicalContext::DeploymentR2 { .. },
            CreatedStage::Managed { receipt: created },
        ) => {
            if let Some(object) = &created.empty {
                return Ok(ClosedStage::Managed {
                    object: object.clone(),
                });
            }
            let upload_id = created
                .upload_id
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("direct managed stage upload absent"))?;
            let object = storage::effect(
                env,
                admission,
                operation_id,
                &(complete, placement_id, upload_id),
                false,
                || managed::complete_checked(env, &key, upload_id, &parts, &before_dispatch),
            )
            .await?;
            Ok(ClosedStage::Managed { object })
        }
        (DirectPhysicalContext::External { .. }, CreatedStage::External { result }) => {
            let upload_id = match &result.outcome {
                ExternalStageOutcome::EmptyClosed { .. } => {
                    return Ok(ClosedStage::External {
                        result: result.clone(),
                    })
                }
                ExternalStageOutcome::Created { upload_id } => upload_id,
                _ => anyhow::bail!("direct external stage create receipt differs"),
            };
            for chunk in parts.chunks(32) {
                let first = chunk
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("direct manifest chunk absent"))?
                    .part
                    .part_number;
                let operation = ExternalStageOperation::FreezeParts {
                    upload_id: upload_id.clone(),
                    manifest: manifest.clone(),
                    first_part: first,
                    parts: chunk.to_vec(),
                };
                let work = crate::external_object::prepare_stage_request_with_cutoff(
                    env,
                    admission,
                    placement_id,
                    step_id(
                        admission,
                        placement_id,
                        &complete.operation_id,
                        &format!("freeze-stage:{first}"),
                    )?,
                    operation,
                    expires_at,
                )
                .await?;
                before_dispatch()?;
                crate::external_object::execute_stage(env, &work).await?;
            }
            let work = crate::external_object::prepare_stage_request_with_cutoff(
                env,
                admission,
                placement_id,
                operation_id,
                ExternalStageOperation::CompleteStage {
                    upload_id: upload_id.clone(),
                    manifest: manifest.clone(),
                },
                expires_at,
            )
            .await?;
            before_dispatch()?;
            Ok(ClosedStage::External {
                result: crate::external_object::execute_stage(env, &work).await?,
            })
        }
        _ => anyhow::bail!("direct stage receipt physical kind differs"),
    }
}

pub(crate) async fn enqueue(env: &Env, job: &VerificationJob) -> Result<()> {
    ensure!(
        encode_direct_control(job)?.len() <= 64 * 1024,
        "direct verification queue message exceeds bound"
    );
    if retained(env, &job.admission, &job.complete, job.placement_id)
        .await?
        .is_some()
    {
        return Ok(());
    }
    admit_read(env, job).await?;
    let binding = if job.admission.intent.dependency_phase == DirectDependencyPhase::Content {
        BULK_QUEUE
    } else {
        METADATA_QUEUE
    };
    let queue = env.queue(binding)?;
    let mut event = observation::Event::new(
        observation::Kind::QueueEnqueue,
        Some(observation_object(job)),
        &uuid::Uuid::new_v4().to_string(),
    );
    event.bytes = Some(WireInteger::new(encode_direct_control(job)?.len() as u64));
    observation::emit(&event);
    let queued = queue.send(job.clone()).await;
    event.outcome = if queued.is_ok() {
        observation::Outcome::Positive
    } else {
        observation::Outcome::Unknown
    };
    observation::emit(&event);
    queued?;
    Ok(())
}

/// Admits the exact original immutable read before either accepted or fixture enqueue.
pub(crate) async fn admit_read(env: &Env, job: &VerificationJob) -> Result<()> {
    if let ClosedStage::External { result } = &job.closed {
        let operation_id = step_id(
            &job.admission,
            job.placement_id,
            &job.complete.operation_id,
            "verify-stage",
        )?;
        let operation = external_verification_operation(result)?;
        if crate::external_object::prepare_stage_read_recovery(
            env,
            &job.admission,
            job.placement_id,
            operation_id.clone(),
            operation.clone(),
        )
        .await
        .is_err()
        {
            let work = crate::external_object::prepare_stage_request(
                env,
                &job.admission,
                job.placement_id,
                operation_id,
                operation,
            )
            .await?;
            // Queue delay never creates a new post-expiry read admission. Only
            // the exact read admitted under the original guard can be resumed.
            crate::external_object::admit_stage_read(env, &work).await?;
        }
    }
    Ok(())
}

/// Uses the same source integrity and capacity path for an isolated admitted fixture.
pub(crate) async fn run_fixture(
    env: &Env,
    job: &VerificationJob,
    authority: &dyn super::authority::StageAuthority,
    maximum_objects: u32,
) -> Result<(VerifiedPlacement, ObjectObservation, bool)> {
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    job.admission.validate(&deployment)?;
    let placement = storage::placement(&job.admission, job.placement_id)?;
    authority.protected_material(env, placement).await?;
    ensure!(
        job.version == 1
            && job.admission.intent.byte_size.get() <= authority.maximum_object_bytes(),
        "qualification immutable read exceeds candidate ceiling"
    );
    let _capacity = Capacity::acquire(job.admission.intent.dependency_phase, maximum_objects)?;
    let observed = object_observation();
    let operation_id = step_id(
        &job.admission,
        job.placement_id,
        &job.complete.operation_id,
        "verify-stage",
    )?;
    let replayed = Cell::new(true);
    let source_dispatch = || replayed.set(false);
    let proof = storage::effect(env, &job.admission, operation_id.clone(), job, true, || {
        verify_observed(env, job, &operation_id, &source_dispatch)
    })
    .await?;
    Ok((proof, observed, replayed.get()))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ObjectObservation {
    pub(crate) aggregate_active: u32,
    pub(crate) bulk_active: u32,
    pub(crate) metadata_active: u32,
}

pub(crate) fn object_observation() -> ObjectObservation {
    ObjectObservation {
        aggregate_active: OBJECT_ACTIVE.with(|n| n.get()),
        bulk_active: BULK_ACTIVE.with(|n| n.get()),
        metadata_active: METADATA_ACTIVE.with(|n| n.get()),
    }
}

pub(crate) async fn run(env: &Env, job: &VerificationJob) -> Result<VerifiedPlacement> {
    let qualified = QualifiedConfig::load(env).await?;
    run_qualified(env, job, &qualified, None)
        .await
        .map(|(proof, _)| proof)
}

async fn run_qualified(
    env: &Env,
    job: &VerificationJob,
    qualified: &QualifiedConfig,
    observed: Option<&observation::Event>,
) -> Result<(VerifiedPlacement, bool)> {
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    ensure!(
        job.version == 1,
        "direct verification queue version unsupported"
    );
    job.admission.validate(&deployment)?;
    let placement = storage::placement(&job.admission, job.placement_id)?;
    qualified.protected(env, placement).await?;
    ensure!(
        job.admission.intent.byte_size.get() <= qualified.runtime.maximum_object_bytes.get(),
        "direct source exceeds accepted capacity"
    );
    let _capacity = Capacity::acquire(
        job.admission.intent.dependency_phase,
        qualified.runtime.maximum_parallel_objects.get() as u32,
    )?;
    if let Some(observed) = observed {
        let mut event = observed.clone();
        let active = object_observation();
        event.aggregate_active = active.aggregate_active;
        event.bulk_active = active.bulk_active;
        event.metadata_active = active.metadata_active;
        observation::emit(&event);
    }
    let operation_id = step_id(
        &job.admission,
        job.placement_id,
        &job.complete.operation_id,
        "verify-stage",
    )?;
    let replayed = Cell::new(true);
    let source_dispatch = || replayed.set(false);
    let proof = storage::effect(env, &job.admission, operation_id.clone(), job, true, || {
        verify_observed(env, job, &operation_id, &source_dispatch)
    })
    .await?;
    Ok((proof, replayed.get()))
}

async fn verify(env: &Env, job: &VerificationJob, operation_id: &str) -> Result<VerifiedPlacement> {
    verify_observed(env, job, operation_id, &|| {}).await
}

async fn verify_observed(
    env: &Env,
    job: &VerificationJob,
    operation_id: &str,
    source_dispatch: &dyn Fn(),
) -> Result<VerifiedPlacement> {
    let class = if job.admission.intent.dependency_phase == DirectDependencyPhase::Content {
        super::provider_capacity::Class::Bulk
    } else {
        super::provider_capacity::Class::Metadata
    };
    let placement = storage::placement(&job.admission, job.placement_id)?;
    let manifest = job
        .complete
        .manifests
        .iter()
        .find(|item| item.placement.placement_id == job.placement_id)
        .ok_or_else(|| anyhow::anyhow!("direct verification manifest absent"))?;
    let parts = load_parts(env, &job.admission, job.placement_id, Some(manifest)).await?;
    let stage_key = direct_staging_key(&job.admission.session_id, placement)?;
    let (incarnation, external_verified, projection) = match &job.closed {
        ClosedStage::Managed { object } => {
            // This helper has no provider-terminal replay: a positive return
            // requires the actual complete source stream and integrity checks.
            source_dispatch();
            managed::verify_class_observed(
                env,
                &stage_key,
                object,
                &job.admission.intent,
                &parts,
                class,
                Some(observation_object(job)),
            )
            .await?;
            let projection = if matches!(&job.admission.intent.target, DirectUploadTarget::CacheObject { path, .. } if path.ends_with(".narinfo"))
            {
                let bytes = managed::read_metadata_class_observed(
                    env,
                    &stage_key,
                    object,
                    512 * 1024,
                    class,
                    Some(observation_object(job)),
                )
                .await?;
                let projection =
                    aos_hub_core::hybrid_ingress::projection::HybridNarinfoProjection::from_bytes(
                        &bytes,
                    )?;
                Some(aos_hub_core::hybrid_ingress::HybridObjectProjection::Narinfo(projection))
            } else {
                None
            };
            (
                DirectObjectIncarnation::ProviderVersion {
                    version: object.version.clone(),
                },
                None,
                projection,
            )
        }
        ClosedStage::External { result } => {
            let stamp = match &result.outcome {
                ExternalStageOutcome::Closed { guard_stamp, .. } => guard_stamp.clone(),
                ExternalStageOutcome::EmptyClosed { guard_stamp, .. } => guard_stamp.clone(),
                _ => anyhow::bail!("direct external stage positive close absent"),
            };
            let operation = external_verification_operation(result)?;
            let work = crate::external_object::prepare_stage_read_recovery(
                env,
                &job.admission,
                job.placement_id,
                operation_id.into(),
                operation,
            )
            .await?;
            let verified = {
                let _capacity = super::provider_capacity::acquire_class(1, class).await?;
                crate::external_object::execute_stage_observed(env, &work, source_dispatch).await?
            };
            ensure!(
                matches!(&verified.outcome, ExternalStageOutcome::Verified { sha256, byte_size, .. } if sha256 == &job.admission.intent.expected_sha256 && byte_size == &job.admission.intent.byte_size),
                "direct external integrity receipt differs"
            );
            let projection = if matches!(&job.admission.intent.target,
                DirectUploadTarget::CacheObject { path, .. } if path.ends_with(".narinfo"))
            {
                let bytes = {
                    let _capacity = super::provider_capacity::acquire_class(1, class).await?;
                    crate::external_object::read_stage_metadata(
                        env,
                        &job.admission,
                        job.placement_id,
                        result,
                        &verified,
                        512 * 1024,
                    )
                    .await?
                };
                Some(aos_hub_core::hybrid_ingress::HybridObjectProjection::Narinfo(
                    aos_hub_core::hybrid_ingress::projection::HybridNarinfoProjection::from_bytes(&bytes)?,
                ))
            } else {
                None
            };
            (
                DirectObjectIncarnation::GuardStamp { stamp },
                Some(verified),
                projection,
            )
        }
    };
    Ok(VerifiedPlacement {
        placement: DirectStagePlacementEvidence {
            placement: manifest.placement.clone(),
            manifest: manifest.clone(),
            verification_operation_id: operation_id.into(),
            staging_incarnation: incarnation,
        },
        closed: job.closed.clone(),
        external_verified,
        sha256: job.admission.intent.expected_sha256.clone(),
        byte_size: job.admission.intent.byte_size,
        projection,
    })
}

fn external_verification_operation(result: &ExternalStageResult) -> Result<ExternalStageOperation> {
    let upload_id = match &result.outcome {
        ExternalStageOutcome::Closed { upload_id, .. } => Some(upload_id.clone()),
        ExternalStageOutcome::EmptyClosed { .. } => None,
        _ => anyhow::bail!("direct external stage positive close absent"),
    };
    Ok(ExternalStageOperation::VerifyClosedStage {
        upload_id,
        close_receipt_digest: result.receipt_digest.clone(),
    })
}

pub(crate) async fn retained(
    env: &Env,
    admission: &DirectUploadAdmission,
    complete: &DirectCompleteRequest,
    placement_id: WireInteger,
) -> Result<Option<VerifiedPlacement>> {
    let operation_id = step_id(
        admission,
        placement_id,
        &complete.operation_id,
        "verify-stage",
    )?;
    let Reply::Effect { effect } =
        storage::call(env, admission, Operation::ReadEffect { operation_id }).await?
    else {
        anyhow::bail!("direct verification journal differs");
    };
    effect
        .and_then(|effect| effect.terminal)
        .map(|value| {
            serde_json::from_value(value)
                .map_err(|_| anyhow::anyhow!("direct integrity receipt malformed"))
        })
        .transpose()
}

struct Capacity {
    active: Rc<Cell<u32>>,
    aggregate: Rc<Cell<u32>>,
}

impl Capacity {
    fn acquire(phase: DirectDependencyPhase, maximum: u32) -> Result<Self> {
        let active = if phase == DirectDependencyPhase::Content {
            BULK_ACTIVE.with(Rc::clone)
        } else {
            METADATA_ACTIVE.with(Rc::clone)
        };
        ensure!(
            maximum >= 2,
            "direct verification requires reserved metadata capacity"
        );
        let ceiling = if phase == DirectDependencyPhase::Content {
            maximum - 1
        } else {
            maximum
        };
        let aggregate = OBJECT_ACTIVE.with(Rc::clone);
        ensure!(
            active.get() < ceiling && aggregate.get() < maximum,
            "direct verification queue at accepted capacity"
        );
        active.set(active.get() + 1);
        aggregate.set(aggregate.get() + 1);
        Ok(Self { active, aggregate })
    }
}

impl Drop for Capacity {
    fn drop(&mut self) {
        self.active.set(self.active.get().saturating_sub(1));
        self.aggregate.set(self.aggregate.get().saturating_sub(1));
    }
}

pub(crate) async fn consume(
    batch: &worker::MessageBatch<aos_hub_core::jobs::JobEnvelope>,
    env: &Env,
) -> worker::Result<()> {
    let expected = batch.queue();
    ensure_queue(&expected, env)?;
    // Fixture deliveries have their own exact signed original and reserved
    // namespace. Ordinary jobs still require the full independent acceptance.
    let qualified = QualifiedConfig::load(env).await.ok();
    let maximum_objects = if let Some(qualified) = &qualified {
        qualified.runtime.maximum_parallel_objects.get()
    } else if super::config::qualification_limits(env)
        .ok()
        .flatten()
        .is_some()
    {
        super::config::integer(env, "HUB_DIRECT_VERIFY_MAX_PARALLEL_OBJECTS")
            .map_err(|_| {
                worker::Error::RustError("qualification queue object bound absent".into())
            })?
            .get()
    } else {
        return Err(worker::Error::RustError(
            "direct queue measured acceptance unavailable".into(),
        ));
    };
    if !(2..=32).contains(&maximum_objects) {
        return Err(worker::Error::RustError(
            "direct queue object bound invalid".into(),
        ));
    }
    let parallel = if expected == env.var("HUB_DIRECT_VERIFY_BULK_NAME")?.to_string() {
        maximum_objects.saturating_sub(1)
    } else {
        maximum_objects
    };
    // Object admission and actual provider requests have independent bounds.
    // A queued object waiting for an SDK slot still occupies its class slot.
    let parallel = parallel as usize;
    let qualified = &qualified;
    let expected = &expected;
    futures_util::stream::iter(batch.raw_iter())
        .map(|message| async move {
            if let Some(outcome) = super::qualification::consume_message(
                message.body(),
                env,
                expected,
                message.id(),
                message.timestamp().as_millis(),
            )
            .await
            {
                if outcome.is_ok() {
                    message.ack();
                } else {
                    message.retry();
                }
                return Ok::<_, worker::Error>(());
            }
            let Some(qualified) = qualified.as_ref() else {
                message.retry();
                return Ok(());
            };
            let job: VerificationJob = match serde_wasm_bindgen::from_value(message.body()) {
                Ok(job) => job,
                Err(_) => {
                    message.retry();
                    return Ok::<_, worker::Error>(());
                }
            };
            // Distinct configured queues cannot silently mix semantic priority and bulk load.
            let kind = if job.admission.intent.dependency_phase == DirectDependencyPhase::Content {
                BULK_QUEUE
            } else {
                METADATA_QUEUE
            };
            if env.var(&format!("{kind}_NAME"))?.to_string() != *expected {
                message.retry();
                return Ok(());
            }
            let mut observed = observation::Event::new(
                observation::Kind::QueueStart,
                Some(observation_object(&job)),
                &uuid::Uuid::new_v4().to_string(),
            );
            observed.delivery_digest = Some(observation::digest(&message.id()));
            let result = run_qualified(env, &job, qualified, Some(&observed)).await;
            observed.kind = observation::Kind::QueueFinish;
            let active = object_observation();
            observed.aggregate_active = active.aggregate_active;
            observed.bulk_active = active.bulk_active;
            observed.metadata_active = active.metadata_active;
            observed.outcome = if result.is_ok() {
                observation::Outcome::Positive
            } else {
                observation::Outcome::Refused
            };
            observed.replayed = result.as_ref().ok().map(|(_, replayed)| *replayed);
            observation::emit(&observed);
            if result.is_ok() {
                message.ack();
                observed.kind = observation::Kind::QueueAck;
            } else {
                message.retry();
                observed.kind = observation::Kind::QueueRetry;
            }
            observation::emit(&observed);
            Ok(())
        })
        .buffer_unordered(parallel)
        .for_each(|result| async move {
            if result.is_err() {
                batch.retry_all();
            }
        })
        .await;
    Ok(())
}

fn ensure_queue(name: &str, env: &Env) -> worker::Result<()> {
    if [BULK_QUEUE, METADATA_QUEUE].iter().any(|binding| {
        env.var(&format!("{binding}_NAME"))
            .is_ok_and(|configured| configured.to_string() == name)
    }) {
        return Ok(());
    }
    Err(worker::Error::RustError(
        "direct verification queue identity differs".into(),
    ))
}
