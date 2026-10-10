//! Validates bounded direct rows independently of source authority.

use super::*;

pub(super) fn validate_claim_geometry(
    claim: &OriginalPublicationClaim,
    limits: OriginalInputLineageLimits,
) -> Result<usize, RuntimeError> {
    validate_bodies(claim, limits)?;
    let edges = claim.rows.iter().try_fold(0usize, |total, row| {
        total
            .checked_add(row.dependencies.len())
            .filter(|total| *total <= limits.maximum_edges)
            .ok_or(RuntimeError::ResourceLimit)
    })?;
    let object_count = claim.rows.len();

    // Each row is expanded once. The queue holds four roots plus at most every
    // declared edge, and integer indices borrow the original typed inventory.
    let queue_capacity = edges.checked_add(4).ok_or(RuntimeError::ResourceLimit)?;
    let mut queue = reserved_vec(queue_capacity)?;
    for reference in [
        &claim.published,
        &claim.origin.observation_batch,
        &claim.origin.stop_receipt,
        &claim.origin.measurement,
    ] {
        queue.push(row_index(claim, reference)?);
    }
    let mut reachable = reserved_vec(object_count)?;
    reachable.resize(object_count, false);
    while let Some(index) = queue.pop() {
        if reachable[index] {
            continue;
        }
        reachable[index] = true;
        for dependency in &claim.rows[index].dependencies {
            queue.push(row_index(claim, dependency)?);
        }
    }
    if reachable.iter().any(|present| !present) {
        return Err(RuntimeError::InvalidReceipt);
    }

    // Leaf-first completion detects cycles. A reusable bitmap determines each
    // complete transitive row before its exact storage credit is reserved.
    let mut completed: Vec<Option<Vec<usize>>> = reserved_vec(object_count)?;
    completed.resize_with(object_count, || None);
    let mut seen = reserved_vec(object_count)?;
    seen.resize(object_count, false);
    let mut derived_edges = 0usize;
    for _ in 0..object_count {
        let index = next_complete_row(claim, &completed)?;
        seen.fill(false);
        for dependency in &claim.rows[index].dependencies {
            let dependency = row_index(claim, dependency)?;
            seen[dependency] = true;
            for descendant in completed[dependency]
                .as_ref()
                .ok_or(RuntimeError::InvalidReceipt)?
            {
                seen[*descendant] = true;
            }
        }
        let transitive_count = seen.iter().filter(|present| **present).count();
        derived_edges = derived_edges
            .checked_add(transitive_count)
            .filter(|total| *total <= limits.maximum_edges)
            .ok_or(RuntimeError::ResourceLimit)?;
        let mut transitive = reserved_vec(transitive_count)?;
        for (dependency, present) in seen.iter().enumerate() {
            if *present {
                transitive.push(dependency);
            }
        }
        completed[index] = Some(transitive);
    }
    Ok(derived_edges)
}

fn validate_bodies(
    claim: &OriginalPublicationClaim,
    limits: OriginalInputLineageLimits,
) -> Result<(), RuntimeError> {
    if claim.objects.len() > limits.maximum_objects
        || claim.rows.len() != claim.objects.len()
        || claim
            .rows
            .windows(2)
            .any(|pair| pair[0].object >= pair[1].object)
        || claim
            .objects
            .windows(2)
            .any(|pair| pair[0].reference >= pair[1].reference)
    {
        return Err(RuntimeError::ResourceLimit);
    }
    let mut bytes = 0usize;
    let mut edges = 0usize;
    for (row, object) in claim.rows.iter().zip(&claim.objects) {
        bytes = bytes
            .checked_add(object.bytes.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        edges = edges
            .checked_add(row.dependencies.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        if bytes > limits.maximum_bytes || edges > limits.maximum_edges {
            return Err(RuntimeError::ResourceLimit);
        }
        if row.object != object.reference
            || object.reference.verify(&object.bytes).is_err()
            || row.dependencies.windows(2).any(|pair| pair[0] >= pair[1])
            || row.dependencies.contains(&row.object)
            || claim.objects.iter().any(|other| {
                other.reference.hash == object.reference.hash
                    && other.reference.length != object.reference.length
            })
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        for dependency in &row.dependencies {
            row_index(claim, dependency)?;
        }
    }
    Ok(())
}

fn row_index(
    claim: &OriginalPublicationClaim,
    reference: &ContentRef,
) -> Result<usize, RuntimeError> {
    claim
        .rows
        .binary_search_by(|row| row.object.cmp(reference))
        .map_err(|_| RuntimeError::InvalidReceipt)
}

fn next_complete_row(
    claim: &OriginalPublicationClaim,
    completed: &[Option<Vec<usize>>],
) -> Result<usize, RuntimeError> {
    for (index, row) in claim.rows.iter().enumerate() {
        if completed[index].is_some() {
            continue;
        }
        let mut ready = true;
        for dependency in &row.dependencies {
            ready &= completed[row_index(claim, dependency)?].is_some();
        }
        if ready {
            return Ok(index);
        }
    }
    Err(RuntimeError::InvalidReceipt)
}

fn reserved_vec<T>(capacity: usize) -> Result<Vec<T>, RuntimeError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    Ok(values)
}
