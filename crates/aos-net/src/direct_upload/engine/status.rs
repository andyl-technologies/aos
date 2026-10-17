//! Bounded status reconciliation against original source and placement custody.

use aos_proto_types::direct_upload::*;

use super::{
    DirectCheckpointStore, DirectClientError, DirectObservedPart, DirectUploadControl,
    DirectUploadObject, helpers,
};
use crate::direct_upload::{PartChecksumAlgorithm, PartSource, provider::portable_part};

pub(super) async fn source_part(
    object: &DirectUploadObject,
    placement: &DirectPlacementRef,
    number: u32,
) -> Result<PartSource, DirectClientError> {
    let (offset, size) = object
        .intent
        .part_range(number)
        .map_err(|_| DirectClientError::Invalid)?;
    let algorithm = match placement.checksum_algorithm {
        DirectChecksumAlgorithm::Md5 => PartChecksumAlgorithm::Md5,
        DirectChecksumAlgorithm::Sha256 => PartChecksumAlgorithm::Sha256,
    };
    object
        .source
        .prepare_part(number, offset, size, algorithm)
        .await
        .map_err(|_| DirectClientError::SourceChanged)
}

pub(super) async fn check_observed(
    object: &DirectUploadObject,
    placement: &DirectPlacementRef,
    observed: &DirectManifestPart,
) -> Result<(), DirectClientError> {
    let source = source_part(object, placement, observed.part.part_number).await?;
    if portable_part(&source) != observed.part || !valid_direct_etag(&observed.etag) {
        return Err(DirectClientError::Invalid);
    }
    Ok(())
}

/// One original Begin projection and its durable pre-admission resume decision.
pub(super) struct ReconcileItem<'a> {
    pub(super) object: &'a DirectUploadObject,
    pub(super) status: DirectSessionStatus,
    pub(super) resumed: bool,
}

struct Progress<'a> {
    original: ReconcileItem<'a>,
    cursor: Option<DirectPartCursor>,
    seen: u64,
    pending: bool,
}

/// Reconciles physical pages before the scheduler can issue any new part grant.
///
/// Logical Begin summaries contain no physical records or pagination cursor.
/// Previously retained sessions therefore need an explicit first Status page.
/// Fresh sessions cannot have prior provider work: durable session admission
/// precedes grants. All continuation queries use the same immutable originals.
pub(super) async fn reconcile_batch<C: DirectUploadControl, S: DirectCheckpointStore>(
    control: &helpers::LimitedControl<'_, C>,
    store: &S,
    items: Vec<ReconcileItem<'_>>,
) -> Result<Vec<DirectSessionStatus>, DirectClientError> {
    let mut progress = Vec::with_capacity(items.len());
    let mut initial_observations = Vec::new();
    for item in items {
        let page = item.status.clone();
        let initial = item.resumed
            && page.state != DirectSessionState::Committed
            && page.parts.is_empty()
            && page.next_cursor.is_none();
        let mut owner = Progress {
            original: item,
            cursor: None,
            seen: 0,
            pending: initial,
        };
        initial_observations.extend(consume_page(&mut owner, &page).await?);
        owner.pending |= initial;
        progress.push(owner);
    }
    if !initial_observations.is_empty() {
        store.record_server_parts(&initial_observations).await?;
    }

    while progress.iter().any(|owner| owner.pending) {
        let (indices, queries) = plan_wave(control, &progress)?;
        let members = queries
            .iter()
            .map(|query| {
                encode_direct_control(query)
                    .map(|bytes| hex::encode(sha2::Sha256::digest(bytes)))
                    .map_err(|_| DirectClientError::Invalid)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let members: Vec<_> = members.iter().map(String::as_str).collect();
        let request = DirectUploadRequest::StatusBatch(DirectBatch {
            operation_id: helpers::operation("status-batch-page", &members),
            items: queries.clone(),
        });
        let response = helpers::control(control, &request).await?;
        if response.sessions.len() != indices.len() || !response.grants.is_empty() {
            return Err(DirectClientError::Invalid);
        }

        let mut remaining = response.sessions;
        let mut observations = Vec::new();
        for (index, query) in indices.into_iter().zip(queries) {
            let position = remaining
                .iter()
                .position(|page| page.session == query.session)
                .ok_or(DirectClientError::Invalid)?;
            let page = remaining.swap_remove(position);
            if page.parts.len() > query.maximum_parts as usize {
                return Err(DirectClientError::Invalid);
            }
            observations.extend(consume_page(&mut progress[index], &page).await?);
        }
        if !remaining.is_empty() {
            return Err(DirectClientError::Invalid);
        }
        // Check every item before persisting the correlated observation wave.
        // A stale or refused neighbor cannot allow any new provider dispatch.
        store.record_server_parts(&observations).await?;
    }

    Ok(progress
        .into_iter()
        .map(|mut owner| {
            owner.original.status.parts.clear();
            owner.original.status.next_cursor = None;
            owner.original.status
        })
        .collect())
}

async fn consume_page(
    owner: &mut Progress<'_>,
    page: &DirectSessionStatus,
) -> Result<Vec<DirectObservedPart>, DirectClientError> {
    let original = &owner.original;
    page.validate_for(
        &original.status.session,
        &original.object.intent,
        &original.object.placements,
    )
    .map_err(|_| DirectClientError::Invalid)?;
    if page.resource_version != original.status.resource_version
        || page.state != original.status.state
    {
        return Err(DirectClientError::Blocked);
    }
    helpers::active_or_verified(page.state)?;
    let maximum = maximum_records(original.object)?;
    let after = owner.cursor.as_ref().map(cursor_position);
    let mut observations = Vec::with_capacity(page.parts.len());
    for part in &page.parts {
        let position = (part.placement.placement_id.get(), part.part_number);
        if after.is_some_and(|after| position <= after) {
            return Err(DirectClientError::Invalid);
        }
        owner.seen = owner
            .seen
            .checked_add(1)
            .filter(|seen| *seen <= maximum)
            .ok_or(DirectClientError::Invalid)?;
        // Unknown checksum-bound UploadPart attempts retain the existing retry
        // rule. No unknown Create/Complete/Promote/Abort state is admitted here.
        if let Some(observed) = &part.observed {
            check_observed(original.object, &part.placement, observed).await?;
            observations.push(DirectObservedPart {
                session: original.status.session.clone(),
                placement: part.placement.clone(),
                observed: observed.clone(),
            });
        }
    }
    if let Some(next) = &page.next_cursor {
        if next.part_number == 0 || after.is_some_and(|after| cursor_position(next) <= after) {
            return Err(DirectClientError::Invalid);
        }
    }
    owner.original.status.outstanding_grants = page.outstanding_grants;
    owner.cursor = page.next_cursor.clone();
    owner.pending = owner.cursor.is_some();
    Ok(observations)
}

fn maximum_records(object: &DirectUploadObject) -> Result<u64, DirectClientError> {
    let parts = object
        .intent
        .part_count()
        .map_err(|_| DirectClientError::Invalid)?;
    u64::from(parts)
        .checked_mul(object.placements.len() as u64)
        .ok_or(DirectClientError::Invalid)
}

fn cursor_position(cursor: &DirectPartCursor) -> (u64, u32) {
    (cursor.placement.placement_id.get(), cursor.part_number)
}

fn plan_wave<C>(
    control: &helpers::LimitedControl<'_, C>,
    progress: &[Progress<'_>],
) -> Result<(Vec<usize>, Vec<DirectStatusQuery>), DirectClientError> {
    let mut indices = Vec::new();
    let mut queries = Vec::new();
    for (index, owner) in progress
        .iter()
        .enumerate()
        .filter(|(_, owner)| owner.pending)
    {
        if queries.len() == control.items.min(control.parts) {
            break;
        }
        indices.push(index);
        queries.push(DirectStatusQuery {
            session: owner.original.status.session.clone(),
            after: owner.cursor.clone(),
            maximum_parts: 1,
        });
        if !wave_fits(control, progress, &indices, &queries)? {
            indices.pop();
            queries.pop();
            break;
        }
    }
    if queries.is_empty() {
        return Err(DirectClientError::Invalid);
    }

    // Distribute the one aggregate part allowance; every original gets a slot
    // before any query grows. Counts also reserve the legal maximum reply bytes.
    let mut remaining = control.parts - queries.len();
    while remaining != 0 {
        let mut grew = false;
        for position in 0..queries.len() {
            let owner = &progress[indices[position]];
            let maximum = maximum_records(owner.original.object)?;
            if u64::from(queries[position].maximum_parts) >= maximum.saturating_sub(owner.seen) {
                continue;
            }
            queries[position].maximum_parts += 1;
            if !wave_fits(control, progress, &indices, &queries)? {
                queries[position].maximum_parts -= 1;
                continue;
            }
            remaining -= 1;
            grew = true;
            if remaining == 0 {
                break;
            }
        }
        if !grew {
            break;
        }
    }
    Ok((indices, queries))
}

fn wave_fits<C>(
    control: &helpers::LimitedControl<'_, C>,
    progress: &[Progress<'_>],
    indices: &[usize],
    queries: &[DirectStatusQuery],
) -> Result<bool, DirectClientError> {
    let request = DirectUploadRequest::StatusBatch(DirectBatch {
        operation_id: "00".repeat(32),
        items: queries.to_vec(),
    });
    let request_bytes = match helpers::request_bytes(&request) {
        Ok(bytes) => bytes,
        Err(DirectClientError::Invalid) => return Ok(false),
        Err(error) => return Err(error),
    };
    if request_bytes > control.bytes {
        return Ok(false);
    }
    let statuses: Vec<_> = indices
        .iter()
        .map(|index| {
            let mut status = progress[*index].original.status.clone();
            status.parts.clear();
            status.next_cursor = None;
            // false has the larger JSON spelling; this field may change on a read.
            status.outstanding_grants = false;
            status
        })
        .collect();
    let response = DirectUploadResponse {
        operation_id: "00".repeat(32),
        sessions: statuses,
        grants: Vec::new(),
        errors: Vec::new(),
    };
    let mut reserved = match encode_direct_control(&response) {
        Ok(bytes) => bytes.len(),
        Err(_) => return Ok(false),
    };
    for (index, query) in indices.iter().zip(queries) {
        let owner = &progress[*index];
        let (part_bytes, cursor_bytes) = maximum_page_bytes(&owner.original.status)?;
        let part_budget = (query.maximum_parts as usize)
            .checked_mul(part_bytes + 1)
            .ok_or(DirectClientError::Invalid)?;
        reserved = reserved
            .checked_add(part_budget)
            .and_then(|bytes| bytes.checked_add(cursor_bytes))
            .ok_or(DirectClientError::Invalid)?;
    }
    Ok(reserved <= control.bytes)
}

/// Reserves serialized field widths, not observations or synthetic authority.
/// Actual replies still pass the shared validator and exact original matching.
fn maximum_page_bytes(status: &DirectSessionStatus) -> Result<(usize, usize), DirectClientError> {
    let mut placement = None;
    let mut placement_bytes = 0;
    for candidate in &status.placements {
        let bytes = encode_direct_control(candidate)
            .map_err(|_| DirectClientError::Invalid)?
            .len();
        if bytes > placement_bytes {
            placement = Some(candidate.clone());
            placement_bytes = bytes;
        }
    }
    let placement = placement.ok_or(DirectClientError::Invalid)?;
    let cursor = DirectPartCursor {
        placement: placement.clone(),
        part_number: u32::MAX,
    };
    let part = DirectPartStatus {
        placement,
        part_number: u32::MAX,
        pending_operation_id: Some("00".repeat(32)),
        unknown: false,
        observed: Some(DirectManifestPart {
            etag: format!("\"{}\"", "a".repeat(1022)),
            part: DirectPart {
                part_number: u32::MAX,
                offset: WireInteger::new(u64::MAX),
                byte_size: WireInteger::new(u64::MAX),
                sha256: "00".repeat(32),
                checksum: DirectPartChecksum {
                    algorithm: DirectChecksumAlgorithm::Sha256,
                    value: "A".repeat(44),
                },
            },
        }),
    };
    Ok((
        encode_direct_control(&part)
            .map_err(|_| DirectClientError::Invalid)?
            .len(),
        encode_direct_control(&cursor)
            .map_err(|_| DirectClientError::Invalid)?
            .len(),
    ))
}

use sha2::Digest as _;
