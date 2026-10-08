//! Authenticated reconstruction of complete per-sandbox historical lease chains.
//!
//! Each sandbox has one acquisition root, exact receipt-authenticated successor
//! fences, at most one pending intent, and one current pointer at its unique
//! completed head. Historical expiry never releases ownership for CAS.

use super::*;

type RecoveredOwnershipState = (
    BTreeMap<[u8; 16], DurableOwnershipEntry>,
    BTreeMap<SandboxId, RecoveredOwnershipLease>,
);

pub(super) fn recover_durable_ownership<'a>(
    operations: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    currents: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    effects: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    idempotency: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    verifier: &OwnershipAuthorityVerifier,
) -> Result<RecoveredOwnershipState, OwnershipHistoryError> {
    let mut entries = BTreeMap::new();
    for (key, value) in operations {
        if entries.len() >= MAXIMUM_DURABLE_ENTRIES {
            return Err(OwnershipHistoryError::CorruptState);
        }
        if !key.starts_with(DURABLE_ENTRY_PREFIX) {
            return Err(OwnershipHistoryError::CorruptState);
        }
        let entry = decode_durable_entry(key, value, verifier)?;
        if entries.insert(*entry.claim.request_id(), entry).is_some() {
            return Err(OwnershipHistoryError::CorruptState);
        }
    }

    let mut pointers = BTreeMap::new();
    for (key, value) in currents {
        if pointers.len() >= MAXIMUM_DURABLE_CURRENT_POINTERS {
            return Err(OwnershipHistoryError::CorruptState);
        }
        if !key.starts_with(DURABLE_CURRENT_PREFIX) {
            return Err(OwnershipHistoryError::CorruptState);
        }
        let (sandbox, request, generation, digest) = decode_current_pointer(key, value)?;

        if pointers
            .insert(sandbox, (request, generation, digest))
            .is_some()
        {
            return Err(OwnershipHistoryError::CorruptState);
        }
    }

    if effects.into_iter().next().is_some() || idempotency.into_iter().next().is_some() {
        return Err(OwnershipHistoryError::CorruptState);
    }

    let mut grouped = BTreeMap::<SandboxId, Vec<_>>::new();
    for (request, entry) in &entries {
        grouped
            .entry(entry.claim.assignment().sandbox())
            .or_default()
            .push((request, entry));
    }
    if pointers
        .keys()
        .any(|sandbox| !grouped.contains_key(sandbox))
    {
        return Err(OwnershipHistoryError::CorruptState);
    }

    let mut current = BTreeMap::new();
    for (sandbox, scoped) in grouped {
        recover_sandbox_chain(sandbox, &scoped, &entries, &pointers, &mut current)?;
    }

    Ok((entries, current))
}

fn recover_sandbox_chain(
    sandbox: SandboxId,
    scoped: &[(&[u8; 16], &DurableOwnershipEntry)],
    entries: &BTreeMap<[u8; 16], DurableOwnershipEntry>,
    pointers: &BTreeMap<SandboxId, ([u8; 16], u64, ObjectDigest)>,
    current: &mut BTreeMap<SandboxId, RecoveredOwnershipLease>,
) -> Result<(), OwnershipHistoryError> {
    let pending: Vec<_> = scoped
        .iter()
        .filter(|(_, entry)| matches!(entry.state, DurableEntryState::Intent))
        .collect();
    if pending.len() > 1 {
        return Err(OwnershipHistoryError::CorruptState);
    }

    let completed: Vec<_> = scoped
        .iter()
        .filter_map(|(request, entry)| match &entry.state {
            DurableEntryState::Intent => None,
            DurableEntryState::Completed { lease, .. } => Some((*request, entry, lease)),
        })
        .collect();
    if completed.is_empty() {
        if pointers.contains_key(&sandbox)
            || pending
                .first()
                .is_some_and(|(_, entry)| entry.claim.action() != OwnershipClaimAction::Acquire)
        {
            return Err(OwnershipHistoryError::CorruptState);
        }
        return Ok(());
    }

    let roots: Vec<_> = completed
        .iter()
        .filter(|(_, entry, _)| entry.claim.action() == OwnershipClaimAction::Acquire)
        .collect();
    if roots.len() != 1 {
        return Err(OwnershipHistoryError::CorruptState);
    }

    let mut by_fence = BTreeMap::new();
    for (request, _, lease) in &completed {
        let fence = (lease.generation(), *lease.digest().as_bytes());
        if by_fence.insert(fence, **request).is_some() {
            return Err(OwnershipHistoryError::CorruptState);
        }
    }

    let mut children = BTreeMap::new();
    for (request, entry, lease) in &completed {
        if entry.claim.action() != OwnershipClaimAction::Acquire {
            let prior = entry
                .claim
                .expected_prior()
                .ok_or(OwnershipHistoryError::CorruptState)?;
            let predecessor = by_fence
                .get(&(prior.generation(), *prior.digest().as_bytes()))
                .ok_or(OwnershipHistoryError::CorruptState)?;
            let predecessor_entry = entries
                .get(predecessor)
                .ok_or(OwnershipHistoryError::CorruptState)?;
            let DurableEntryState::Completed {
                lease: predecessor_lease,
                ..
            } = &predecessor_entry.state
            else {
                return Err(OwnershipHistoryError::CorruptState);
            };
            if lease.generation() <= predecessor_lease.generation()
                || !transition::is_valid_successor(&entry.claim, predecessor_lease)
                || children.insert(*predecessor, **request).is_some()
            {
                return Err(OwnershipHistoryError::CorruptState);
            }
        }
    }

    let mut visited = BTreeSet::new();
    let mut head_request = *roots[0].0;
    loop {
        if !visited.insert(head_request) {
            return Err(OwnershipHistoryError::CorruptState);
        }
        match children.get(&head_request) {
            Some(next) => head_request = *next,
            None => break,
        }
    }
    if visited.len() != completed.len() {
        return Err(OwnershipHistoryError::CorruptState);
    }

    let head = entries
        .get(&head_request)
        .ok_or(OwnershipHistoryError::CorruptState)?;
    let DurableEntryState::Completed {
        lease: head_lease, ..
    } = &head.state
    else {
        return Err(OwnershipHistoryError::CorruptState);
    };
    if pointers.get(&sandbox) != Some(&(head_request, head_lease.generation(), head_lease.digest()))
    {
        return Err(OwnershipHistoryError::CorruptState);
    }

    if let Some((_, pending_entry)) = pending.first() {
        validate_claim_against_current(
            &pending_entry.claim,
            &BTreeMap::from([(sandbox, head_lease.as_ref().clone())]),
        )
        .map_err(|_| OwnershipHistoryError::CorruptState)?;
    }

    current.insert(sandbox, head_lease.as_ref().clone());
    Ok(())
}
