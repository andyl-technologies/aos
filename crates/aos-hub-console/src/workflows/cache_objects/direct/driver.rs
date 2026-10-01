//! Ordered browser control phases and bounded parallel private UploadPart work.

use aos_proto_types::direct_upload::*;
use futures::{stream, StreamExt as _, TryStreamExt as _};
use serde::Serialize;
use web_sys::File;

use crate::direct_upload_model::{
    operation_id, validate_object_size, GrantLifetime, PartCheckpoint, PartDispatchContext,
    PartReceipt, ResumeHead, SourcePart, BROWSER_PART_BYTES,
};
use crate::transport::ApiClient;

use super::{browser_now, checkpoint::Checkpoint, source};

const PAUSED: &str = "Upload progress was preserved. Choose the same original file to resume";

/// Uploads one exact cache file through admitted private staging and guarded promotion.
///
/// # Errors
/// Returns an error for changed source/actor/profile, failed checkpoint persistence,
/// refused controls or pending effects. Original control intents remain resumable.
pub(crate) async fn upload(
    client: ApiClient,
    capabilities: DirectUploadCapabilities,
    path: String,
    file: File,
) -> Result<String, String> {
    let DirectCapabilitiesTarget::Cache { cache_id } = &capabilities.target else {
        return Err("The Hub did not resolve the selected cache owner".into());
    };
    let target = DirectUploadTarget::CacheObject {
        cache_id: cache_id.clone(),
        path,
    };
    target
        .validate()
        .map_err(|_| "The cache object path is invalid".to_string())?;
    let client = client.with_direct_upload_capabilities(capabilities.clone());
    let scope = operation_id(
        "scope",
        &capabilities.deployment_id,
        &(&capabilities.principal_id, &target),
    )?;
    let active_key = format!("{scope}:active");
    let size = source::file_size(&file)?;
    validate_object_size(&capabilities, size)?;
    let checkpoint = Checkpoint::open().await?;
    let (sha256, parts) = source::inspect(&file).await?;
    let fresh = discovery(&client, capabilities.target.clone()).await?;
    fresh
        .validate_actor_for(&capabilities.deployment_id, &capabilities.principal_id)
        .map_err(|_| "The authenticated upload actor changed".to_string())?;
    if fresh.transfer_mode != DirectAdvertisedTransferMode::DirectRequired
        || fresh.profiles != capabilities.profiles
        || fresh.minimum_object_bytes != capabilities.minimum_object_bytes
    {
        return Err("The reviewed upload destinations changed while the source was read".into());
    }
    validate_object_size(&fresh, size)?;

    let mut head = match checkpoint.get::<ResumeHead>(&active_key).await? {
        Some(head) => {
            head.intent
                .validate()
                .map_err(|_| "The original browser upload record is invalid".to_string())?;
            if head.scope != scope
                || head.deployment_id != fresh.deployment_id
                || head.principal_id != fresh.principal_id
                || head.intent.target != target
                || head.intent.expected_sha256 != sha256
                || head.intent.byte_size.get() != size
                || head.intent.part_size.get() != BROWSER_PART_BYTES
                || !valid_direct_digest(&head.run_nonce)
            {
                return Err("This path has a retained upload for another source or identity; choose its original file to resume".into());
            }
            head
        }
        None => {
            let run_nonce = random_nonce()?;
            let dependency_phase = if matches!(&target, DirectUploadTarget::CacheObject { path, .. } if path.ends_with(".narinfo"))
            {
                DirectDependencyPhase::LeafMetadata
            } else {
                DirectDependencyPhase::Content
            };
            let intent = DirectUploadIntent {
                version: 1,
                client_operation_id: operation_id("object", &run_nonce, &target)?,
                target,
                expected_sha256: sha256,
                byte_size: WireInteger::new(size),
                part_size: WireInteger::new(BROWSER_PART_BYTES),
                dependency_phase,
                transfer_mode: DirectTransferMode::DirectRequired,
            };
            intent
                .validate()
                .map_err(|_| "The selected file has unsupported upload geometry".to_string())?;
            let head = ResumeHead {
                scope,
                run_nonce,
                deployment_id: fresh.deployment_id.clone(),
                principal_id: fresh.principal_id.clone(),
                intent,
                session: None,
                complete: None,
            };
            checkpoint.put(&active_key, &head).await?
        }
    };

    let begin = DirectBeginBatch {
        operation_id: operation_id("begin", &head.run_nonce, &head.intent)?,
        items: vec![head.intent.clone()],
    };
    DirectUploadRequest::BeginBatch(begin.clone())
        .validate()
        .map_err(|_| "The upload admission exceeds its control limit".to_string())?;
    let reply = control(
        &client,
        &head,
        aos_proto_types::DIRECT_UPLOAD_SERVICE_BEGIN_BATCH_PATH,
        &begin,
        &begin.operation_id,
    )
    .await?;
    let status = one_status(&reply)?;
    if status.intent != head.intent {
        return Err("The Hub changed the original upload source".into());
    }
    fresh
        .validate_placements_for(&fresh.target, &status.placements, browser_now()?)
        .map_err(|_| "The Hub changed the reviewed upload destinations".to_string())?;
    if let Some(original) = &head.session {
        status
            .validate_for(&original.session, &head.intent, &original.placements)
            .map_err(|_| "The Hub changed the original browser upload session".to_string())?;
    }
    head.session = Some(status);
    head = checkpoint.put(&active_key, &head).await?;
    if matches!(session(&head)?.state, DirectSessionState::Committed) {
        checkpoint.retire_active(&active_key, &head).await?;
        return Ok(format!("Uploaded {size} bytes"));
    }
    if matches!(
        session(&head)?.state,
        DirectSessionState::Creating
            | DirectSessionState::BlockedUnknown
            | DirectSessionState::CleanupPending
            | DirectSessionState::Aborted
    ) {
        return Err(PAUSED.into());
    }

    initialize_parts(&checkpoint, &head, &parts).await?;
    refresh_status(&client, &checkpoint, &mut head, &active_key, &parts).await?;
    if head.complete.is_none() {
        upload_missing(&client, &checkpoint, &head, &fresh, &file, &parts).await?;
        refresh_status(&client, &checkpoint, &mut head, &active_key, &parts).await?;
        head.complete = Some(complete_intent(&checkpoint, &head, &parts).await?);
        head = checkpoint.put(&active_key, &head).await?;
    }
    let original = head
        .complete
        .clone()
        .ok_or_else(|| "The original complete intent is missing".to_string())?;
    let request = DirectBatch {
        operation_id: operation_id("complete-batch", &head.run_nonce, &original)?,
        items: vec![original],
    };
    DirectUploadRequest::CompleteBatch(request.clone())
        .validate()
        .map_err(|_| "The complete control exceeds its byte limit".to_string())?;
    for _ in 0..8 {
        let reply = control(
            &client,
            &head,
            aos_proto_types::DIRECT_UPLOAD_SERVICE_COMPLETE_BATCH_PATH,
            &request,
            &request.operation_id,
        )
        .await?;
        let status = one_status(&reply)?;
        status
            .validate_for(
                &session(&head)?.session,
                &head.intent,
                &session(&head)?.placements,
            )
            .map_err(|_| "The Hub changed the original completion session".to_string())?;
        let state = status.state;
        head.session = Some(status);
        head = checkpoint.put(&active_key, &head).await?;
        if state == DirectSessionState::Committed {
            checkpoint.retire_active(&active_key, &head).await?;
            return Ok(format!(
                "Uploaded {size} bytes with verified direct storage"
            ));
        }
        if matches!(
            state,
            DirectSessionState::BlockedUnknown
                | DirectSessionState::CleanupPending
                | DirectSessionState::Aborted
        ) {
            return Err(PAUSED.into());
        }
    }
    Err(PAUSED.into())
}

async fn initialize_parts(
    checkpoint: &Checkpoint,
    head: &ResumeHead,
    parts: &[SourcePart],
) -> Result<(), String> {
    let mut wave = Vec::new();
    for placement in &session(head)?.placements {
        for original in parts {
            let key = part_key(head, placement, original.number);
            if let Some(retained) = checkpoint.get::<PartCheckpoint>(&key).await? {
                if retained.placement != *placement
                    || retained.original != *original
                    || retained.attempt == 0
                {
                    return Err("The original browser part record changed".into());
                }
                continue;
            }
            let record = PartCheckpoint {
                placement: placement.clone(),
                original: original.clone(),
                attempt: 1,
                receipt: None,
                server_observed: None,
            };
            push_record(checkpoint, &mut wave, key, &record).await?;
        }
    }
    if !wave.is_empty() {
        checkpoint.put_wave(&wave).await?;
    }
    Ok(())
}

async fn push_record<T: Serialize>(
    checkpoint: &Checkpoint,
    wave: &mut Vec<(String, Vec<u8>)>,
    key: String,
    value: &T,
) -> Result<(), String> {
    let bytes = encode_direct_control(value)
        .map_err(|_| "The browser upload record exceeds its limit".to_string())?;
    let current: usize = wave
        .iter()
        .map(|(key, value)| key.len() + value.len())
        .sum();
    if wave.len() == MAX_DIRECT_BATCH_ITEMS
        || current + key.len() + bytes.len() > MAX_DIRECT_CONTROL_BYTES
    {
        checkpoint.put_wave(wave).await?;
        wave.clear();
    }
    wave.push((key, bytes));
    Ok(())
}

async fn refresh_status(
    client: &ApiClient,
    checkpoint: &Checkpoint,
    head: &mut ResumeHead,
    active_key: &str,
    parts: &[SourcePart],
) -> Result<(), String> {
    let mut after = None;
    loop {
        let query = DirectStatusQuery {
            session: session(head)?.session.clone(),
            after: after.clone(),
            maximum_parts: MAX_DIRECT_BATCH_PARTS as u32,
        };
        let request = DirectBatch {
            operation_id: operation_id("status", &head.run_nonce, &query)?,
            items: vec![query],
        };
        let reply = control(
            client,
            head,
            aos_proto_types::DIRECT_UPLOAD_SERVICE_STATUS_BATCH_PATH,
            &request,
            &request.operation_id,
        )
        .await?;
        let status = one_status(&reply)?;
        status
            .validate_for(
                &session(head)?.session,
                &head.intent,
                &session(head)?.placements,
            )
            .map_err(|_| "The Hub changed the original resume declaration".to_string())?;
        let mut wave = Vec::new();
        for observed in &status.parts {
            let original = parts
                .get(observed.part_number.saturating_sub(1) as usize)
                .ok_or_else(|| "The Hub returned an unexpected upload part".to_string())?;
            let key = part_key(head, &observed.placement, observed.part_number);
            let mut record = checkpoint
                .get::<PartCheckpoint>(&key)
                .await?
                .ok_or_else(|| "The original browser part record is missing".to_string())?;
            if record.placement != observed.placement || record.original != *original {
                return Err("The Hub changed the original part destination".into());
            }
            if let Some(member) = &observed.observed {
                member
                    .part
                    .validate(&head.intent)
                    .map_err(|_| "The Hub returned an invalid observed part".to_string())?;
                if member.part != original.descriptor(record.placement.checksum_algorithm)? {
                    return Err("The Hub changed the original observed part bytes".into());
                }
                record.server_observed = Some(member.clone());
                push_record(checkpoint, &mut wave, key, &record).await?;
            }
        }
        if !wave.is_empty() {
            checkpoint.put_wave(&wave).await?;
        }
        let next = status.next_cursor.clone();
        head.session = Some(status);
        *head = checkpoint.put(active_key, head).await?;
        if next.is_none() {
            break;
        }
        if let Some(next) = &next {
            let next_position = (next.placement.placement_id.get(), next.part_number);
            if after.as_ref().is_some_and(|old: &DirectPartCursor| {
                next_position <= (old.placement.placement_id.get(), old.part_number)
            }) {
                return Err("The Hub repeated or reversed an upload progress page".into());
            }
        }
        after = next;
    }
    Ok(())
}

async fn upload_missing(
    client: &ApiClient,
    checkpoint: &Checkpoint,
    head: &ResumeHead,
    capabilities: &DirectUploadCapabilities,
    file: &File,
    parts: &[SourcePart],
) -> Result<(), String> {
    let mut wave = Vec::new();
    for placement in &session(head)?.placements {
        for original in parts {
            let key = part_key(head, placement, original.number);
            let record = checkpoint
                .get::<PartCheckpoint>(&key)
                .await?
                .ok_or_else(|| "The original browser part record is missing".to_string())?;
            if record.receipt.is_some() || record.server_observed.is_some() {
                continue;
            }
            let item = grant_request(head, &record)?;
            let mut candidate = wave.clone();
            candidate.push((key.clone(), record.clone(), item.clone()));
            // Sixteen maximum-size delegated URLs still fit the whole reply;
            // provider requests within that batch run with concurrency four.
            if !wave.is_empty()
                && (wave.len() == 16
                    || grant_batch(head, &candidate)
                        .and_then(|request| {
                            request
                                .validate()
                                .map_err(|_| "The grant control exceeds its limit".to_string())
                        })
                        .is_err())
            {
                transfer_wave(client, checkpoint, head, capabilities, file, &wave).await?;
                wave.clear();
            }
            wave.push((key, record, item));
        }
    }
    if !wave.is_empty() {
        transfer_wave(client, checkpoint, head, capabilities, file, &wave).await?;
    }
    // Re-report locally retained positive receipts even if a prior Report reply was lost.
    let mut reports = Vec::new();
    for placement in &session(head)?.placements {
        for original in parts {
            let record = checkpoint
                .get::<PartCheckpoint>(&part_key(head, placement, original.number))
                .await?
                .ok_or_else(|| "The browser part record is missing".to_string())?;
            if let Some(receipt) = record.receipt {
                let report = DirectPartReport {
                    session: session(head)?.session.clone(),
                    placement: placement.clone(),
                    operation_id: operation_id("report", &head.run_nonce, &(&placement, &receipt))?,
                    grant_id: receipt.grant_id,
                    grant_revision: receipt.grant_revision,
                    observed: receipt.observed,
                };
                let mut candidate = reports.clone();
                candidate.push(report.clone());
                if !reports.is_empty()
                    && (reports.len() == MAX_DIRECT_BATCH_PARTS
                        || report_batch(head, &candidate)
                            .and_then(|request| {
                                request
                                    .validate()
                                    .map_err(|_| "The report control exceeds its limit".to_string())
                            })
                            .is_err())
                {
                    report_wave(client, head, &reports).await?;
                    reports.clear();
                }
                reports.push(report);
            }
        }
    }
    if !reports.is_empty() {
        report_wave(client, head, &reports).await?;
    }
    Ok(())
}

type Work = (String, PartCheckpoint, DirectGrantPartRequest);

fn grant_request(
    head: &ResumeHead,
    record: &PartCheckpoint,
) -> Result<DirectGrantPartRequest, String> {
    let part = record
        .original
        .descriptor(record.placement.checksum_algorithm)?;
    Ok(DirectGrantPartRequest {
        session: session(head)?.session.clone(),
        placement: record.placement.clone(),
        operation_id: operation_id(
            "grant",
            &head.run_nonce,
            &(&record.placement, &part, record.attempt),
        )?,
        part,
    })
}

fn grant_batch(head: &ResumeHead, wave: &[Work]) -> Result<DirectUploadRequest, String> {
    let items: Vec<_> = wave.iter().map(|(_, _, request)| request.clone()).collect();
    Ok(DirectUploadRequest::GrantPartsBatch(DirectBatch {
        operation_id: operation_id("grant-batch", &head.run_nonce, &items)?,
        items,
    }))
}

fn report_batch(
    head: &ResumeHead,
    items: &[DirectPartReport],
) -> Result<DirectUploadRequest, String> {
    Ok(DirectUploadRequest::ReportPartsBatch(DirectBatch {
        operation_id: operation_id("report-batch", &head.run_nonce, &items)?,
        items: items.to_vec(),
    }))
}

async fn report_wave(
    client: &ApiClient,
    head: &ResumeHead,
    reports: &[DirectPartReport],
) -> Result<(), String> {
    let DirectUploadRequest::ReportPartsBatch(request) = report_batch(head, reports)? else {
        return Err("The report control is invalid".into());
    };
    control(
        client,
        head,
        aos_proto_types::DIRECT_UPLOAD_SERVICE_REPORT_PARTS_BATCH_PATH,
        &request,
        &request.operation_id,
    )
    .await?;
    Ok(())
}

async fn transfer_wave(
    client: &ApiClient,
    checkpoint: &Checkpoint,
    head: &ResumeHead,
    capabilities: &DirectUploadCapabilities,
    file: &File,
    wave: &[Work],
) -> Result<(), String> {
    let DirectUploadRequest::GrantPartsBatch(request) = grant_batch(head, wave)? else {
        return Err("The grant control is invalid".into());
    };
    let reply = control(
        client,
        head,
        aos_proto_types::DIRECT_UPLOAD_SERVICE_GRANT_PARTS_BATCH_PATH,
        &request,
        &request.operation_id,
    )
    .await?;
    if reply.grants.len() != wave.len() {
        return Err("The Hub returned an incomplete delegated grant batch".into());
    }
    let mut work = Vec::new();
    for (key, record, expected) in wave {
        let grant = reply
            .grants
            .iter()
            .find(|grant| {
                grant.placement == expected.placement
                    && grant.part.part_number == expected.part.part_number
            })
            .ok_or_else(|| "The Hub omitted an original delegated part".to_string())?;
        let retained = PartDispatchContext {
            session: expected.session.clone(),
            placement: expected.placement.clone(),
            intent: head.intent.clone(),
            part: expected.part.clone(),
        };
        match retained.classify(grant, browser_now()?)? {
            GrantLifetime::Expired => {
                let mut next = record.clone();
                next.attempt = next
                    .attempt
                    .checked_add(1)
                    .ok_or_else(|| "The original grant attempt counter overflowed".to_string())?;
                checkpoint.put(key, &next).await?;
                return Err(PAUSED.into());
            }
            GrantLifetime::Expiring => return Err(PAUSED.into()),
            GrantLifetime::Ready => {}
        }
        let profile = capabilities
            .profiles
            .iter()
            .find(|profile| profile.placement_id == expected.placement.placement_id)
            .ok_or_else(|| "The reviewed provider profile is missing".to_string())?;
        work.push((
            key.clone(),
            record.clone(),
            grant.clone(),
            profile.clone(),
            retained,
        ));
    }
    stream::iter(
        work.into_iter()
            .map(|(key, mut record, grant, profile, retained)| async move {
                let body = source::verified_part(file, &record.original).await?;
                let first = client
                    .put_direct_part(&grant, &profile, &body, &retained)
                    .await;
                let etag = match first {
                    Err(crate::transport::TransportError::DirectPartUnknown) => {
                        // UploadPart overwrites only this exact content-bound range.
                        // A fresh Request streams the SAME immutable Blob once more;
                        // close, promotion and other unknown effects never use this rule.
                        client
                            .put_direct_part(&grant, &profile, &body, &retained)
                            .await
                            .map_err(|_| PAUSED.to_string())?
                    }
                    result => result.map_err(|_| PAUSED.to_string())?,
                };
                record.receipt = Some(PartReceipt {
                    grant_id: grant.grant_id,
                    grant_revision: grant.grant_revision,
                    observed: DirectManifestPart {
                        part: grant.part,
                        etag,
                    },
                });
                checkpoint.put(&key, &record).await?;
                Ok::<_, String>(())
            }),
    )
    .buffer_unordered(4)
    .try_collect::<Vec<_>>()
    .await?;
    Ok(())
}

async fn complete_intent(
    checkpoint: &Checkpoint,
    head: &ResumeHead,
    parts: &[SourcePart],
) -> Result<DirectCompleteRequest, String> {
    let mut manifests = Vec::new();
    for placement in &session(head)?.placements {
        let mut hasher = DirectManifestHasher::new(&head.intent, placement)
            .map_err(|_| "The original manifest geometry is invalid".to_string())?;
        for original in parts {
            let record = checkpoint
                .get::<PartCheckpoint>(&part_key(head, placement, original.number))
                .await?
                .ok_or_else(|| "The original browser part receipt is missing".to_string())?;
            let member = record
                .server_observed
                .or_else(|| record.receipt.map(|receipt| receipt.observed))
                .ok_or_else(|| {
                    "The original upload has an unobserved part; progress was preserved".to_string()
                })?;
            hasher
                .push(&member)
                .map_err(|_| "The original manifest changed its source or ordering".to_string())?;
        }
        manifests.push(DirectManifestCommitment {
            placement: placement.clone(),
            manifest_digest: hasher
                .finish()
                .map_err(|_| "The original manifest is incomplete".to_string())?,
            part_count: head
                .intent
                .part_count()
                .map_err(|_| "The original geometry is invalid".to_string())?,
        });
    }
    Ok(DirectCompleteRequest {
        session: session(head)?.session.clone(),
        operation_id: operation_id("complete", &head.run_nonce, &manifests)?,
        expected_resource_version: session(head)?.resource_version,
        manifests,
    })
}

async fn discovery(
    client: &ApiClient,
    target: DirectCapabilitiesTarget,
) -> Result<DirectUploadCapabilities, String> {
    let result: DirectUploadCapabilities = client
        .call_direct(
            aos_proto_types::DIRECT_UPLOAD_SERVICE_GET_CAPABILITIES_PATH,
            &DirectGetCapabilities {
                target: target.clone(),
            },
        )
        .await
        .map_err(|_| {
            "Authenticated upload discovery failed; no body fallback was used".to_string()
        })?;
    result
        .validate_at_for(&target, browser_now()?)
        .map_err(|_| "The Hub returned invalid or expired upload discovery".to_string())?;
    Ok(result)
}

async fn control<T: Serialize>(
    client: &ApiClient,
    head: &ResumeHead,
    path: &str,
    request: &T,
    operation: &str,
) -> Result<DirectUploadResponse, String> {
    let DirectUploadTarget::CacheObject { cache_id, .. } = &head.intent.target else {
        return Err("The original cache owner is invalid".into());
    };
    let target = DirectCapabilitiesTarget::Cache {
        cache_id: cache_id.clone(),
    };
    let reply: DirectUploadResponse = client
        .call_direct_for_actor(
            path,
            request,
            &head.deployment_id,
            &head.principal_id,
            &target,
        )
        .await
        .map_err(|_| PAUSED.to_string())?;
    reply
        .validate()
        .map_err(|_| "The Hub returned invalid bounded upload metadata".to_string())?;
    if reply.operation_id != operation || !reply.errors.is_empty() {
        return Err(PAUSED.into());
    }
    Ok(reply)
}

fn one_status(reply: &DirectUploadResponse) -> Result<DirectSessionStatus, String> {
    if reply.sessions.len() != 1 {
        return Err("The Hub returned an incomplete upload session".into());
    }
    reply
        .sessions
        .first()
        .cloned()
        .ok_or_else(|| "The original upload session is missing".into())
}

fn session(head: &ResumeHead) -> Result<&DirectSessionStatus, String> {
    head.session
        .as_ref()
        .ok_or_else(|| "The original browser upload session is missing".into())
}

fn part_key(head: &ResumeHead, placement: &DirectPlacementRef, number: u32) -> String {
    format!(
        "{}:{}:{}:{number}",
        head.scope,
        head.run_nonce,
        placement.placement_id.get()
    )
}

fn random_nonce() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    web_sys::window()
        .ok_or_else(|| "The browser secure random source is unavailable".to_string())?
        .crypto()
        .map_err(|_| "The browser secure random source is unavailable".to_string())?
        .get_random_values_with_u8_array(&mut bytes)
        .map_err(|_| "The browser secure random source is unavailable".to_string())?;
    Ok(hex::encode(bytes))
}
