//! Exact immutable journal identities and atomic before-dispatch reservations.

use aos_proto_types::direct_upload::*;
use async_trait::async_trait;
use rusqlite::Transaction;
use serde::{Deserialize, Serialize};

use super::{DirectRetainedCompletion, SqliteDirectCheckpoints, sqlite};
use crate::direct_upload::{
    DirectCheckpointStore, DirectClientError, DirectGrantAttempt, DirectObservedPart,
    DirectPartReceipt,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    session: DirectSessionRef,
    intent: DirectUploadIntent,
    placements: Vec<DirectPlacementRef>,
}

impl Session {
    fn from_status(status: &DirectSessionStatus) -> Result<Self, DirectClientError> {
        status
            .validate()
            .map_err(|_| DirectClientError::Checkpoint)?;
        Ok(Self {
            session: status.session.clone(),
            intent: status.intent.clone(),
            placements: status.placements.clone(),
        })
    }
}

fn scope(
    transaction: &Transaction<'_>,
    session: &DirectSessionRef,
    placement: Option<&DirectPlacementRef>,
) -> Result<Session, DirectClientError> {
    session
        .validate()
        .map_err(|_| DirectClientError::Checkpoint)?;
    let record: Session = sqlite::read(
        transaction,
        "session",
        &format!("session-{}", session.session_id),
        0,
        0,
    )?
    .ok_or(DirectClientError::Checkpoint)?;
    let retained_intent: DirectUploadIntent = sqlite::read(
        transaction,
        "intent",
        &record.intent.client_operation_id,
        0,
        0,
    )?
    .ok_or(DirectClientError::Checkpoint)?;
    record
        .intent
        .validate()
        .map_err(|_| DirectClientError::Checkpoint)?;
    if record.intent != retained_intent
        || &record.session != session
        || placement.is_some_and(|placement| !record.placements.contains(placement))
    {
        return Err(DirectClientError::Checkpoint);
    }
    Ok(record)
}

fn observed(
    transaction: &Transaction<'_>,
    session: &DirectSessionRef,
    placement: &DirectPlacementRef,
    value: &DirectManifestPart,
) -> Result<(), DirectClientError> {
    let record = scope(transaction, session, Some(placement))?;
    value
        .part
        .validate(&record.intent)
        .map_err(|_| DirectClientError::Checkpoint)?;
    if value.part.checksum.algorithm != placement.checksum_algorithm
        || !valid_direct_etag(&value.etag)
    {
        return Err(DirectClientError::Checkpoint);
    }
    Ok(())
}

fn bound<T: Serialize>(values: &[T]) -> Result<(), DirectClientError> {
    if values.len() > MAX_DIRECT_BATCH_ITEMS {
        return Err(DirectClientError::Checkpoint);
    }
    // A wave's durable payload shares the same aggregate bound as its control.
    encode_direct_control(&values).map_err(|_| DirectClientError::Checkpoint)?;
    Ok(())
}

fn receipt(
    transaction: &Transaction<'_>,
    value: &DirectPartReceipt,
) -> Result<(), DirectClientError> {
    observed(
        transaction,
        &value.session,
        &value.placement,
        &value.observed,
    )?;
    if !valid_direct_digest(&value.grant_id) || value.grant_revision.get() == 0 {
        return Err(DirectClientError::Checkpoint);
    }
    let attempt: u64 = sqlite::read(
        transaction,
        "grant",
        &value.session.session_id,
        value.placement.placement_id.get(),
        value.observed.part.part_number,
    )?
    .ok_or(DirectClientError::Checkpoint)?;
    if attempt == 0 {
        return Err(DirectClientError::Checkpoint);
    }
    sqlite::immutable(
        transaction,
        "receipt",
        &value.session.session_id,
        value.placement.placement_id.get(),
        value.observed.part.part_number,
        value,
    )
}

pub(super) fn complete(
    transaction: &Transaction<'_>,
    request: &DirectCompleteRequest,
) -> Result<DirectCompleteRequest, DirectClientError> {
    let record = scope(transaction, &request.session, None)?;
    DirectUploadRequest::CompleteBatch(DirectBatch {
        operation_id: request.operation_id.clone(),
        items: vec![request.clone()],
    })
    .validate()
    .map_err(|_| DirectClientError::Checkpoint)?;
    let count = record
        .intent
        .part_count()
        .map_err(|_| DirectClientError::Checkpoint)?;
    if request.manifests.len() != record.placements.len()
        || request
            .manifests
            .iter()
            .zip(&record.placements)
            .any(|(manifest, placement)| {
                &manifest.placement != placement || manifest.part_count != count
            })
    {
        return Err(DirectClientError::Checkpoint);
    }
    match sqlite::read::<DirectCompleteRequest>(
        transaction,
        "complete",
        &request.session.session_id,
        0,
        0,
    )? {
        Some(previous)
            if previous.session == request.session
                && previous.operation_id == request.operation_id
                && previous.manifests == request.manifests =>
        {
            Ok(previous)
        }
        Some(_) => Err(DirectClientError::Checkpoint),
        None => {
            sqlite::write(
                transaction,
                "complete",
                &request.session.session_id,
                0,
                0,
                request,
            )?;
            Ok(request.clone())
        }
    }
}

impl SqliteDirectCheckpoints {
    /// Finds exact original completions before a restarted file wave can replay Begin.
    ///
    /// A completed local request is only a replay handle. The later final barrier
    /// still needs a current authenticated server response for every owner.
    ///
    /// # Errors
    /// Refuses changed source declarations, torn local custody or excessive waves.
    pub async fn retained_completions(
        &self,
        intents: &[DirectUploadIntent],
    ) -> Result<Vec<Option<DirectRetainedCompletion>>, DirectClientError> {
        if intents.is_empty() || intents.len() > MAX_DIRECT_BATCH_ITEMS {
            return Err(DirectClientError::Checkpoint);
        }
        bound(intents)?;
        let mut identities = std::collections::BTreeSet::new();
        for intent in intents {
            intent
                .validate()
                .map_err(|_| DirectClientError::Checkpoint)?;
            if !identities.insert(&intent.client_operation_id) {
                return Err(DirectClientError::Checkpoint);
            }
        }

        let intents = intents.to_vec();
        let reservation = self.reserve().await?;
        self.wave(reservation, move |transaction| {
            let mut completions = Vec::with_capacity(intents.len());
            for intent in &intents {
                let original: Option<DirectUploadIntent> =
                    sqlite::read(transaction, "intent", &intent.client_operation_id, 0, 0)?;
                if original.as_ref().is_some_and(|original| original != intent) {
                    return Err(DirectClientError::Checkpoint);
                }
                let Some(session) = sqlite::read::<Session>(
                    transaction,
                    "session",
                    &format!("client-{}", intent.client_operation_id),
                    0,
                    0,
                )?
                else {
                    completions.push(None);
                    continue;
                };
                if original.is_none() || &session.intent != intent {
                    return Err(DirectClientError::Checkpoint);
                }
                let request: Option<DirectCompleteRequest> =
                    sqlite::read(transaction, "complete", &session.session.session_id, 0, 0)?;
                completions.push(match request {
                    Some(request) => {
                        let placements: Vec<_> = request
                            .manifests
                            .iter()
                            .map(|manifest| manifest.placement.clone())
                            .collect();
                        if session.session != request.session || session.placements != placements {
                            return Err(DirectClientError::Checkpoint);
                        }
                        Some(DirectRetainedCompletion {
                            request: complete(transaction, &request)?,
                            intent: intent.clone(),
                        })
                    }
                    None => None,
                });
            }
            Ok(completions)
        })
        .await
    }
}

#[async_trait]
impl DirectCheckpointStore for SqliteDirectCheckpoints {
    async fn admit_intents(&self, intents: &[DirectUploadIntent]) -> Result<(), DirectClientError> {
        let _reservation = self.reserve().await?;
        for intent in intents {
            intent
                .validate()
                .map_err(|_| DirectClientError::Checkpoint)?;
        }
        bound(intents)?;
        let intents = intents.to_vec();
        self.wave(_reservation, move |transaction| {
            for intent in &intents {
                sqlite::immutable(
                    transaction,
                    "intent",
                    &intent.client_operation_id,
                    0,
                    0,
                    intent,
                )?;
            }
            Ok(())
        })
        .await
    }

    async fn admit_intent(&self, intent: &DirectUploadIntent) -> Result<(), DirectClientError> {
        self.admit_intents(std::slice::from_ref(intent)).await
    }

    async fn admit_sessions(
        &self,
        statuses: &[DirectSessionStatus],
    ) -> Result<(), DirectClientError> {
        let _reservation = self.reserve().await?;
        bound(statuses)?;
        let sessions: Vec<Session> = statuses
            .iter()
            .map(Session::from_status)
            .collect::<Result<_, _>>()?;
        self.wave(_reservation, move |transaction| {
            for session in &sessions {
                let intent: DirectUploadIntent = sqlite::read(
                    transaction,
                    "intent",
                    &session.intent.client_operation_id,
                    0,
                    0,
                )?
                .ok_or(DirectClientError::Checkpoint)?;
                if intent != session.intent {
                    return Err(DirectClientError::Checkpoint);
                }
                sqlite::immutable(
                    transaction,
                    "session",
                    &format!("session-{}", session.session.session_id),
                    0,
                    0,
                    session,
                )?;
                // One source/owner operation can never adopt a replacement session.
                sqlite::immutable(
                    transaction,
                    "session",
                    &format!("client-{}", session.intent.client_operation_id),
                    0,
                    0,
                    session,
                )?;
            }
            Ok(())
        })
        .await
    }

    async fn admit_session(&self, status: &DirectSessionStatus) -> Result<(), DirectClientError> {
        self.admit_sessions(std::slice::from_ref(status)).await
    }

    async fn grant_attempts(
        &self,
        attempts: &[DirectGrantAttempt],
    ) -> Result<Vec<u64>, DirectClientError> {
        let _reservation = self.reserve().await?;
        bound(attempts)?;
        for attempt in attempts {
            attempt
                .session
                .validate()
                .map_err(|_| DirectClientError::Checkpoint)?;
            attempt
                .placement
                .validate()
                .map_err(|_| DirectClientError::Checkpoint)?;
        }
        let attempts = attempts.to_vec();
        self.wave(_reservation, move |transaction| {
            let mut result = Vec::with_capacity(attempts.len());
            let mut unique = std::collections::BTreeSet::new();
            for attempt in &attempts {
                let record = scope(transaction, &attempt.session, Some(&attempt.placement))?;
                record
                    .intent
                    .part_range(attempt.part_number)
                    .map_err(|_| DirectClientError::Checkpoint)?;
                let placement = attempt.placement.placement_id.get();
                if !unique.insert((
                    attempt.session.session_id.clone(),
                    placement,
                    attempt.part_number,
                )) {
                    return Err(DirectClientError::Checkpoint);
                }
                let previous: Option<u64> = sqlite::read(
                    transaction,
                    "grant",
                    &attempt.session.session_id,
                    placement,
                    attempt.part_number,
                )?;
                let ordinal = match previous {
                    Some(0) => return Err(DirectClientError::Checkpoint),
                    Some(previous) if !attempt.refresh => previous,
                    Some(previous) => previous
                        .checked_add(1)
                        .ok_or(DirectClientError::Checkpoint)?,
                    None => 1,
                };
                sqlite::write(
                    transaction,
                    "grant",
                    &attempt.session.session_id,
                    placement,
                    attempt.part_number,
                    &ordinal,
                )?;
                result.push(ordinal);
            }
            Ok(result)
        })
        .await
    }

    async fn grant_attempt(
        &self,
        session: &DirectSessionRef,
        placement: &DirectPlacementRef,
        part_number: u32,
        refresh: bool,
    ) -> Result<u64, DirectClientError> {
        self.grant_attempts(&[DirectGrantAttempt {
            session: session.clone(),
            placement: placement.clone(),
            part_number,
            refresh,
        }])
        .await?
        .into_iter()
        .next()
        .ok_or(DirectClientError::Checkpoint)
    }

    async fn receipt(
        &self,
        session: &DirectSessionRef,
        placement: &DirectPlacementRef,
        part_number: u32,
    ) -> Result<Option<DirectPartReceipt>, DirectClientError> {
        let _reservation = self.reserve().await?;
        let session = session.clone();
        let placement = placement.clone();
        self.wave(_reservation, move |transaction| {
            let record = scope(transaction, &session, Some(&placement))?;
            record
                .intent
                .part_range(part_number)
                .map_err(|_| DirectClientError::Checkpoint)?;
            let result: Option<DirectPartReceipt> = sqlite::read(
                transaction,
                "receipt",
                &session.session_id,
                placement.placement_id.get(),
                part_number,
            )?;
            if let Some(value) = &result {
                if value.session != session
                    || value.placement != placement
                    || value.observed.part.part_number != part_number
                {
                    return Err(DirectClientError::Checkpoint);
                }
                receipt(transaction, value)?;
            }
            Ok(result)
        })
        .await
    }

    async fn record_receipts(
        &self,
        receipts: &[DirectPartReceipt],
    ) -> Result<(), DirectClientError> {
        let _reservation = self.reserve().await?;
        bound(receipts)?;
        let receipts = receipts.to_vec();
        self.wave(_reservation, move |transaction| {
            for value in &receipts {
                receipt(transaction, value)?;
            }
            Ok(())
        })
        .await
    }

    async fn record_receipt(&self, value: &DirectPartReceipt) -> Result<(), DirectClientError> {
        self.record_receipts(std::slice::from_ref(value)).await
    }

    async fn record_server_parts(
        &self,
        parts: &[DirectObservedPart],
    ) -> Result<(), DirectClientError> {
        let _reservation = self.reserve().await?;
        bound(parts)?;
        let parts = parts.to_vec();
        self.wave(_reservation, move |transaction| {
            for item in &parts {
                observed(transaction, &item.session, &item.placement, &item.observed)?;
                sqlite::immutable(
                    transaction,
                    "observed",
                    &item.session.session_id,
                    item.placement.placement_id.get(),
                    item.observed.part.part_number,
                    &item.observed,
                )?;
            }
            Ok(())
        })
        .await
    }

    async fn record_server_part(
        &self,
        session: &DirectSessionRef,
        placement: &DirectPlacementRef,
        value: &DirectManifestPart,
    ) -> Result<(), DirectClientError> {
        self.record_server_parts(&[DirectObservedPart {
            session: session.clone(),
            placement: placement.clone(),
            observed: value.clone(),
        }])
        .await
    }

    async fn observed_part(
        &self,
        session: &DirectSessionRef,
        placement: &DirectPlacementRef,
        part_number: u32,
    ) -> Result<Option<DirectManifestPart>, DirectClientError> {
        let _reservation = self.reserve().await?;
        let session = session.clone();
        let placement = placement.clone();
        self.wave(_reservation, move |transaction| {
            let record = scope(transaction, &session, Some(&placement))?;
            record
                .intent
                .part_range(part_number)
                .map_err(|_| DirectClientError::Checkpoint)?;
            let value: Option<DirectManifestPart> = sqlite::read(
                transaction,
                "observed",
                &session.session_id,
                placement.placement_id.get(),
                part_number,
            )?;
            if let Some(value) = &value {
                if value.part.part_number != part_number {
                    return Err(DirectClientError::Checkpoint);
                }
                observed(transaction, &session, &placement, value)?;
            }
            Ok(value)
        })
        .await
    }

    async fn admit_completes(
        &self,
        requests: &[DirectCompleteRequest],
    ) -> Result<Vec<DirectCompleteRequest>, DirectClientError> {
        let _reservation = self.reserve().await?;
        bound(requests)?;
        let requests = requests.to_vec();
        self.wave(_reservation, move |transaction| {
            requests
                .iter()
                .map(|request| complete(transaction, request))
                .collect()
        })
        .await
    }

    async fn admit_complete(
        &self,
        request: &DirectCompleteRequest,
    ) -> Result<DirectCompleteRequest, DirectClientError> {
        self.admit_completes(std::slice::from_ref(request))
            .await?
            .into_iter()
            .next()
            .ok_or(DirectClientError::Checkpoint)
    }

    async fn retained_complete(
        &self,
        session: &DirectSessionRef,
    ) -> Result<Option<DirectCompleteRequest>, DirectClientError> {
        session
            .validate()
            .map_err(|_| DirectClientError::Checkpoint)?;
        let session = session.clone();
        let reservation = self.reserve().await?;
        self.wave(reservation, move |transaction| {
            let request: Option<DirectCompleteRequest> =
                sqlite::read(transaction, "complete", &session.session_id, 0, 0)?;
            request
                .map(|request| complete(transaction, &request))
                .transpose()
        })
        .await
    }
}

pub(super) fn original_intent(
    transaction: &Transaction<'_>,
    session: &DirectSessionRef,
) -> Result<DirectUploadIntent, DirectClientError> {
    Ok(scope(transaction, session, None)?.intent)
}
