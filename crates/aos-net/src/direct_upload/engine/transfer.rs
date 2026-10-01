//! Bounded multi-object and multi-placement scheduling with retained retries.

use aos_proto_types::direct_upload::*;
use futures_util::{StreamExt as _, stream};

use super::{
    DirectCheckpointStore, DirectClientError, DirectGrantAttempt, DirectObservedPart,
    DirectPartReceipt, DirectPartTransport, DirectUploadControl, DirectUploadObject, helpers,
    status,
};
use crate::direct_upload::{PartSource, ProviderContext, ProviderError, provider::portable_part};

const MAX_ACTIVE_BULK_FILES: usize = 8;
const MAX_ACTIVE_METADATA_FILES: usize = 32;
const MAX_PARTS_PER_FILE: usize = 4;
const MAX_PROVIDER_REQUESTS: usize = 32;

struct Work {
    object: DirectUploadObject,
    status: DirectSessionStatus,
    placement_index: usize,
    next_part: u32,
}

struct PartJob {
    work_index: usize,
    placement: DirectPlacementRef,
    source: PartSource,
    receipt: Option<DirectPartReceipt>,
    attempt: u64,
    refresh: bool,
}

/// Stages a bounded batch directly and returns actual retained completion states.
///
/// Each batch contains at most 64 independent objects. Provider work uses at
/// most 32 requests, eight active bulk files, four parts per file, or 32 small
/// metadata files. Caller orchestration streams subsequent batches and keeps
/// final publication behind the server's authoritative graph/visibility barrier.
/// `CompletingStaging` is pending server verification, while `StagedVerified`
/// is verified but still cannot commit release visibility.
///
/// Checkpoint intents and grant ordinals are durable before remote effects.
/// Content-bound UploadPart transport retry is separate from unknown provider
/// Create/Complete/Promote/Abort, which cannot be advanced by this engine.
///
/// # Errors
///
/// Refuses changed declarations or checkpoints, malformed/cross-scope replies,
/// changed sources, refused operations, blocked control outcomes or exhausted
/// bounded part retries. No failed direct request uses an application-body API.
pub async fn upload_direct_batch<
    C: DirectUploadControl,
    S: DirectCheckpointStore,
    P: DirectPartTransport,
>(
    control: &C,
    store: &S,
    provider: &P,
    objects: Vec<DirectUploadObject>,
) -> Result<Vec<DirectSessionStatus>, DirectClientError> {
    if objects.is_empty() || objects.len() > MAX_DIRECT_BATCH_ITEMS {
        return Err(DirectClientError::Invalid);
    }
    let mut identities = std::collections::BTreeSet::new();
    for object in &objects {
        object
            .intent
            .validate()
            .map_err(|_| DirectClientError::Invalid)?;
        if !identities.insert(&object.intent.client_operation_id)
            || object.source.byte_size() != object.intent.byte_size.get()
            || object.source.sha256() != object.intent.expected_sha256
            || object.source.part_size() != object.intent.part_size.get()
            || object.placements.len() > MAX_DIRECT_PLACEMENTS
        {
            return Err(DirectClientError::Invalid);
        }
        object
            .discovery
            .validate_at_for(&helpers::discovery_target(&object.discovery), latest_now()?)
            .map_err(|_| DirectClientError::Invalid)?;
        if object.discovery.transfer_mode != DirectAdvertisedTransferMode::DirectRequired
            || object.intent.byte_size.get() < object.discovery.minimum_object_bytes.get()
            || object.intent.byte_size.get() > object.discovery.maximum_object_bytes.get()
            || object.intent.part_size.get() < object.discovery.minimum_part_bytes.get()
            || object.intent.part_size.get() > object.discovery.maximum_part_bytes.get()
        {
            return Err(DirectClientError::Invalid);
        }
        match (&object.intent.target, &object.discovery.target) {
            (
                DirectUploadTarget::CacheObject { cache_id, .. },
                DirectCapabilitiesTarget::Cache { cache_id: owner },
            ) if cache_id == owner => {}
            (
                DirectUploadTarget::PublicationObject { publication_id, .. },
                DirectCapabilitiesTarget::Publication {
                    publication_id: owner,
                },
            ) if publication_id == owner => {}
            (
                DirectUploadTarget::OciBlob { .. },
                DirectCapabilitiesTarget::OciRepository { .. },
            ) => {}
            _ => return Err(DirectClientError::Invalid),
        }
        let mut previous = 0;
        for placement in &object.placements {
            placement
                .validate()
                .map_err(|_| DirectClientError::Invalid)?;
            if placement.placement_id.get() <= previous {
                return Err(DirectClientError::Invalid);
            }
            previous = placement.placement_id.get();
        }
    }
    let limited = helpers::LimitedControl {
        inner: control,
        bytes: objects
            .iter()
            .map(|object| object.discovery.maximum_control_bytes as usize)
            .min()
            .ok_or(DirectClientError::Invalid)?,
        items: objects
            .iter()
            .map(|object| object.discovery.maximum_batch_items as usize)
            .min()
            .ok_or(DirectClientError::Invalid)?,
        parts: objects
            .iter()
            .map(|object| object.discovery.maximum_batch_parts as usize)
            .min()
            .ok_or(DirectClientError::Invalid)?,
    };
    if objects.len() > limited.items {
        return Err(DirectClientError::Invalid);
    }
    let control = &limited;
    // Complete local admission precedes even the first partial Begin effect.
    store
        .admit_intents(
            &objects
                .iter()
                .map(|object| object.intent.clone())
                .collect::<Vec<_>>(),
        )
        .await?;
    let begin_members: Vec<&str> = objects
        .iter()
        .map(|object| object.intent.client_operation_id.as_str())
        .collect();
    let response = helpers::control(
        control,
        &DirectUploadRequest::BeginBatch(DirectBeginBatch {
            operation_id: helpers::operation("begin-batch", &begin_members),
            items: objects.iter().map(|object| object.intent.clone()).collect(),
        }),
    )
    .await?;
    if response.sessions.len() != objects.len() || !response.grants.is_empty() {
        return Err(DirectClientError::Invalid);
    }
    let mut sessions = response.sessions;
    let mut work = Vec::with_capacity(objects.len());
    let mut admitted = Vec::with_capacity(objects.len());
    for mut object in objects {
        let index = sessions
            .iter()
            .position(|status| {
                status.intent.client_operation_id == object.intent.client_operation_id
            })
            .ok_or(DirectClientError::Invalid)?;
        let session = sessions.swap_remove(index);
        object
            .discovery
            .validate_placements_for(
                &helpers::discovery_target(&object.discovery),
                &session.placements,
                latest_now()?,
            )
            .map_err(|_| DirectClientError::Invalid)?;
        if object.placements.is_empty() {
            object.placements = session.placements.clone();
        }
        session
            .validate_for(&session.session, &object.intent, &object.placements)
            .map_err(|_| DirectClientError::Invalid)?;
        admitted.push(session.clone());
        work.push(Work {
            object,
            status: session,
            placement_index: 0,
            next_part: 1,
        });
    }

    store.admit_sessions(&admitted).await?;
    for owner in &mut work {
        if owner.status.state == DirectSessionState::CompletingStaging {
            let original = store
                .retained_complete(&owner.status.session)
                .await?
                .ok_or(DirectClientError::Checkpoint)?;
            if original.session != owner.status.session {
                return Err(DirectClientError::Checkpoint);
            }
            // A pending server hash has no new part work. The retained
            // manifest is checked again before replaying Complete below.
            owner.status.parts.clear();
            continue;
        }
        owner.status =
            status::reconcile(control, store, &owner.object, owner.status.clone()).await?;
    }

    loop {
        let mut jobs = collect_jobs(store, &mut work, limited.parts).await?;
        if jobs.is_empty() {
            if work.iter().any(|owner| {
                owner.status.state == DirectSessionState::Active
                    && owner.placement_index < owner.object.placements.len()
            }) {
                continue;
            }
            break;
        }
        let mut reports: Vec<DirectPartReport> = Vec::with_capacity(jobs.len());
        reserve_attempts(store, &work, &mut jobs, false).await?;
        for retry in 0..3 {
            let requested: Vec<DirectGrantPartRequest> = jobs
                .iter()
                .filter(|job| job.receipt.is_none())
                .map(|job| grant_request(job, &work))
                .collect();
            let mut grants = if requested.is_empty() {
                Vec::new()
            } else {
                let members: Vec<&str> = requested
                    .iter()
                    .map(|request| request.operation_id.as_str())
                    .collect();
                let response = helpers::control(
                    control,
                    &DirectUploadRequest::GrantPartsBatch(DirectBatch {
                        operation_id: helpers::operation("grant-batch", &members),
                        items: requested,
                    }),
                )
                .await?;
                if !response.sessions.is_empty() {
                    return Err(DirectClientError::Invalid);
                }
                response.grants
            };
            let expected_grants = jobs.iter().filter(|job| job.receipt.is_none()).count();
            if grants.len() != expected_grants {
                return Err(DirectClientError::Invalid);
            }
            let mut pending = Vec::with_capacity(jobs.len());
            let mut ready = Vec::with_capacity(jobs.len());
            for job in jobs {
                if let Some(receipt) = &job.receipt {
                    validate_receipt(&work[job.work_index], &job, receipt)?;
                    reports.push(report(receipt));
                    continue;
                }
                let session = &work[job.work_index].status.session;
                let index = grants
                    .iter()
                    .position(|grant| {
                        grant.session_id == session.session_id
                            && grant.placement == job.placement
                            && grant.part.part_number == job.source.identity().part_number
                    })
                    .ok_or(DirectClientError::Invalid)?;
                let grant = grants.swap_remove(index);
                if grant.logical_fingerprint != session.logical_fingerprint
                    || grant.part != portable_part(&job.source)
                {
                    return Err(DirectClientError::Invalid);
                }
                ready.push((job, grant));
            }
            let results: Vec<_> = stream::iter(ready.into_iter().map(|(job, grant)| {
                let owner = &work[job.work_index];
                async move {
                    let context = ProviderContext {
                        session: owner.status.session.clone(),
                        placement: job.placement.clone(),
                        intent: owner.object.intent.clone(),
                    };
                    let result = provider.send_part(&context, &job.source, &grant).await;
                    (job, grant, result)
                }
            }))
            .buffer_unordered(MAX_PROVIDER_REQUESTS)
            .collect()
            .await;
            let mut receipts = Vec::with_capacity(results.len());
            let mut failure = None;
            for (mut job, grant, result) in results {
                match result {
                    Ok(observed) => {
                        status::check_observed(
                            &work[job.work_index].object,
                            &job.placement,
                            &observed,
                        )
                        .await?;
                        let receipt = DirectPartReceipt {
                            session: work[job.work_index].status.session.clone(),
                            placement: job.placement.clone(),
                            grant_id: grant.grant_id,
                            grant_revision: grant.grant_revision,
                            observed,
                        };
                        reports.push(report(&receipt));
                        receipts.push(receipt);
                    }
                    Err(ProviderError::Denied | ProviderError::Expired) if retry < 2 => {
                        job.refresh = true;
                        pending.push(job);
                    }
                    Err(ProviderError::Unavailable) if retry < 2 => pending.push(job),
                    Err(ProviderError::Unavailable | ProviderError::Expired) => {
                        failure = Some(DirectClientError::PartUnavailable);
                    }
                    Err(ProviderError::Denied) => failure = Some(DirectClientError::Denied),
                    Err(_) => failure = Some(DirectClientError::Invalid),
                }
            }
            store.record_receipts(&receipts).await?;
            if let Some(error) = failure {
                return Err(error);
            }
            jobs = pending;
            reserve_attempts(store, &work, &mut jobs, true).await?;
            if jobs.is_empty() {
                break;
            }
        }
        if !jobs.is_empty() {
            return Err(DirectClientError::PartUnavailable);
        }
        reports.sort_by_key(|report| {
            (
                report.session.session_id.clone(),
                report.placement.placement_id.get(),
                report.observed.part.part_number,
            )
        });
        let members: Vec<&str> = reports
            .iter()
            .map(|report| report.operation_id.as_str())
            .collect();
        let response = helpers::control(
            control,
            &DirectUploadRequest::ReportPartsBatch(DirectBatch {
                operation_id: helpers::operation("report-batch", &members),
                items: reports.clone(),
            }),
        )
        .await?;
        if !response.grants.is_empty() {
            return Err(DirectClientError::Invalid);
        }
        let observations: Vec<_> = reports
            .into_iter()
            .map(|report| DirectObservedPart {
                session: report.session,
                placement: report.placement,
                observed: report.observed,
            })
            .collect();
        store.record_server_parts(&observations).await?;
    }
    finish_batch(control, store, work).await
}

async fn collect_jobs<S: DirectCheckpointStore>(
    store: &S,
    work: &mut [Work],
    maximum_parts: usize,
) -> Result<Vec<PartJob>, DirectClientError> {
    let mut jobs = Vec::with_capacity(maximum_parts);
    let mut bulk_files = 0;
    let mut metadata_files = 0;
    for (work_index, owner) in work.iter_mut().enumerate() {
        if owner.status.state != DirectSessionState::Active
            || owner.placement_index >= owner.object.placements.len()
        {
            continue;
        }
        let small = owner
            .object
            .intent
            .part_count()
            .map_err(|_| DirectClientError::Invalid)?
            <= 1;
        if small {
            if metadata_files >= MAX_ACTIVE_METADATA_FILES {
                continue;
            }
            metadata_files += 1;
        } else {
            if bulk_files >= MAX_ACTIVE_BULK_FILES {
                continue;
            }
            bulk_files += 1;
        }
        let mut assigned = 0;
        while owner.placement_index < owner.object.placements.len()
            && assigned < MAX_PARTS_PER_FILE
            && jobs.len() < maximum_parts
        {
            let placement = owner.object.placements[owner.placement_index].clone();
            let part_count = owner
                .object
                .intent
                .part_count()
                .map_err(|_| DirectClientError::Invalid)?;
            if owner.next_part > part_count {
                owner.placement_index += 1;
                owner.next_part = 1;
                continue;
            }
            let number = owner.next_part;
            owner.next_part = owner
                .next_part
                .checked_add(1)
                .ok_or(DirectClientError::Invalid)?;
            if let Some(observed) = store
                .observed_part(&owner.status.session, &placement, number)
                .await?
            {
                status::check_observed(&owner.object, &placement, &observed).await?;
                continue;
            }
            let source = status::source_part(&owner.object, &placement, number).await?;
            let receipt = store
                .receipt(&owner.status.session, &placement, number)
                .await?;
            jobs.push(PartJob {
                work_index,
                placement,
                source,
                receipt,
                attempt: 0,
                refresh: false,
            });
            assigned += 1;
        }
        if jobs.len() == maximum_parts {
            break;
        }
    }
    Ok(jobs)
}

fn grant_request(job: &PartJob, work: &[Work]) -> DirectGrantPartRequest {
    let session = &work[job.work_index].status.session;
    DirectGrantPartRequest {
        session: session.clone(),
        placement: job.placement.clone(),
        operation_id: helpers::operation(
            "grant-part",
            &[
                &session.session_id,
                &session.logical_fingerprint,
                &job.placement.placement_id.get().to_string(),
                &job.placement.placement_fingerprint,
                &job.source.identity().part_number.to_string(),
                &job.attempt.to_string(),
            ],
        ),
        part: portable_part(&job.source),
    }
}

async fn reserve_attempts<S: DirectCheckpointStore>(
    store: &S,
    work: &[Work],
    jobs: &mut [PartJob],
    refresh_only: bool,
) -> Result<(), DirectClientError> {
    let indices: Vec<_> = jobs
        .iter()
        .enumerate()
        .filter(|(_, job)| job.receipt.is_none() && (!refresh_only || job.refresh))
        .map(|(index, _)| index)
        .collect();
    if indices.is_empty() {
        return Ok(());
    }
    let attempts: Vec<_> = indices
        .iter()
        .map(|index| {
            let job = &jobs[*index];
            DirectGrantAttempt {
                session: work[job.work_index].status.session.clone(),
                placement: job.placement.clone(),
                part_number: job.source.identity().part_number,
                refresh: job.refresh,
            }
        })
        .collect();
    let counters = store.grant_attempts(&attempts).await?;
    if counters.len() != indices.len() {
        return Err(DirectClientError::Checkpoint);
    }
    for (index, counter) in indices.into_iter().zip(counters) {
        jobs[index].attempt = counter;
        jobs[index].refresh = false;
    }
    Ok(())
}

fn validate_receipt(
    work: &Work,
    job: &PartJob,
    receipt: &DirectPartReceipt,
) -> Result<(), DirectClientError> {
    if receipt.session != work.status.session
        || receipt.placement != job.placement
        || receipt.observed.part != portable_part(&job.source)
        || !valid_direct_etag(&receipt.observed.etag)
        || !valid_direct_digest(&receipt.grant_id)
        || receipt.grant_revision.get() == 0
    {
        return Err(DirectClientError::Invalid);
    }
    Ok(())
}

fn report(receipt: &DirectPartReceipt) -> DirectPartReport {
    DirectPartReport {
        session: receipt.session.clone(),
        placement: receipt.placement.clone(),
        operation_id: helpers::operation(
            "report-part",
            &[
                &receipt.session.session_id,
                &receipt.grant_id,
                &receipt.grant_revision.get().to_string(),
                &receipt.observed.etag,
            ],
        ),
        grant_id: receipt.grant_id.clone(),
        grant_revision: receipt.grant_revision,
        observed: receipt.observed.clone(),
    }
}

async fn finish_batch<C: DirectUploadControl, S: DirectCheckpointStore>(
    control: &C,
    store: &S,
    work: Vec<Work>,
) -> Result<Vec<DirectSessionStatus>, DirectClientError> {
    let mut complete = Vec::with_capacity(work.len());
    let mut finished = Vec::with_capacity(work.len());
    for owner in &work {
        if owner.status.state == DirectSessionState::Committed {
            finished.push(owner.status.clone());
            continue;
        }
        let mut manifests = Vec::with_capacity(owner.object.placements.len());
        let part_count = owner
            .object
            .intent
            .part_count()
            .map_err(|_| DirectClientError::Invalid)?;
        for placement in &owner.object.placements {
            let mut hash = DirectManifestHasher::new(&owner.object.intent, placement)
                .map_err(|_| DirectClientError::Invalid)?;
            for number in 1..=part_count {
                let observed = store
                    .observed_part(&owner.status.session, placement, number)
                    .await?
                    .ok_or(DirectClientError::Checkpoint)?;
                status::check_observed(&owner.object, placement, &observed).await?;
                hash.push(&observed)
                    .map_err(|_| DirectClientError::Invalid)?;
            }
            manifests.push(DirectManifestCommitment {
                placement: placement.clone(),
                manifest_digest: hash.finish().map_err(|_| DirectClientError::Invalid)?,
                part_count,
            });
        }
        let manifest_bytes =
            encode_direct_control(&manifests).map_err(|_| DirectClientError::Invalid)?;
        let manifest_digest = hex::encode(sha2::Sha256::digest(&manifest_bytes));
        let request = DirectCompleteRequest {
            session: owner.status.session.clone(),
            operation_id: helpers::operation(
                "complete",
                &[
                    &owner.status.session.session_id,
                    &owner.status.session.logical_fingerprint,
                    &manifest_digest,
                ],
            ),
            expected_resource_version: owner.status.resource_version,
            manifests,
        };
        complete.push(request);
    }
    if complete.is_empty() {
        return Ok(finished);
    }
    let retained = store.admit_completes(&complete).await?;
    if retained.len() != complete.len()
        || retained.iter().zip(&complete).any(|(retained, proposed)| {
            retained.session != proposed.session
                || retained.operation_id != proposed.operation_id
                || retained.manifests != proposed.manifests
                || retained.expected_resource_version.get() == 0
        })
    {
        return Err(DirectClientError::Checkpoint);
    }
    complete = retained;
    let members: Vec<&str> = complete
        .iter()
        .map(|request| request.operation_id.as_str())
        .collect();
    let response = helpers::control(
        control,
        &DirectUploadRequest::CompleteBatch(DirectBatch {
            operation_id: helpers::operation("complete-batch", &members),
            items: complete.clone(),
        }),
    )
    .await?;
    if response.sessions.len() != complete.len() || !response.grants.is_empty() {
        return Err(DirectClientError::Invalid);
    }
    for session in response.sessions {
        let owner = work
            .iter()
            .find(|owner| owner.status.session == session.session)
            .ok_or(DirectClientError::Invalid)?;
        if !complete
            .iter()
            .any(|request| request.session == session.session)
        {
            return Err(DirectClientError::Invalid);
        }
        session
            .validate_for(
                &owner.status.session,
                &owner.object.intent,
                &owner.object.placements,
            )
            .map_err(|_| DirectClientError::Invalid)?;
        if !matches!(
            session.state,
            DirectSessionState::CompletingStaging
                | DirectSessionState::StagedVerified
                | DirectSessionState::Committed
        ) {
            return Err(DirectClientError::Blocked);
        }
        finished.push(session);
    }
    Ok(finished)
}

use sha2::Digest as _;

fn latest_now() -> Result<u64, DirectClientError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| DirectClientError::Invalid)?
        .as_secs()
        .checked_add(10)
        .ok_or(DirectClientError::Invalid)
}
