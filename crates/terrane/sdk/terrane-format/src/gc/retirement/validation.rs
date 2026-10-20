//! Checks D-82 represented key, artifact and progress invariants.
//!
//! Claims remain untrusted: these checks cannot establish secure randomness,
//! complete current roots, current permission, immutable continuity or a clock.

pub(super) mod fence;
mod transitions;

/// Returns the predecessor revision encoded by an exact canonical fence key.
///
/// # Errors
/// Rejects a malformed fence key or noncanonical revision.
pub(super) fn fence_revision(pointer: &RecordPointer) -> Result<u64, RetirementError> {
    Ok(fence::fence_pointer(pointer)?.1)
}

use super::*;
use alloc::format;

pub(super) fn decimal(value: &str) -> Result<u64, RetirementError> {
    if value.is_empty()
        || value.len() > 1 && value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(RetirementError::Schema);
    }
    value.parse().map_err(|_| RetirementError::Schema)
}

fn hex<const N: usize>(value: &str) -> Result<[u8; N], RetirementError> {
    if value.len() != N * 2 {
        return Err(RetirementError::Schema);
    }
    let mut output = [0; N];
    for (byte, pair) in output.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        fn digit(value: u8) -> Result<u8, RetirementError> {
            match value {
                b'0'..=b'9' => Ok(value - b'0'),
                b'a'..=b'f' => Ok(value - b'a' + 10),
                _ => Err(RetirementError::Schema),
            }
        }
        *byte = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(output)
}

pub(super) fn operation_key(key: &str) -> Result<(u64, [u8; 16], [u8; 32]), RetirementError> {
    let mut parts = key.split('/');
    if parts.next() != Some("gc") {
        return Err(RetirementError::Schema);
    }
    let cycle = decimal(parts.next().ok_or(RetirementError::Schema)?)?;
    if parts.next() != Some("delete") {
        return Err(RetirementError::Schema);
    }
    let pack = hex(parts.next().ok_or(RetirementError::Schema)?)?;
    let nonce = hex(parts.next().ok_or(RetirementError::Schema)?)?;
    if parts.next().is_some() {
        return Err(RetirementError::Schema);
    }
    Ok((cycle, pack, nonce))
}

/// Returns the original cycle, event proposal nonce and progress revision.
///
/// # Errors
/// Rejects an unknown key shape, noncanonical integer or malformed nonce.
pub(super) fn pass_key(key: &str) -> Result<(u64, [u8; 32], u64), RetirementError> {
    let mut parts = key.split('/');
    if parts.next() != Some("gc") {
        return Err(RetirementError::Schema);
    }
    let cycle = decimal(parts.next().ok_or(RetirementError::Schema)?)?;
    if parts.next() != Some("reconcile") {
        return Err(RetirementError::Schema);
    }
    let nonce = hex(parts.next().ok_or(RetirementError::Schema)?)?;
    let revision = decimal(parts.next().ok_or(RetirementError::Schema)?)?;
    if parts.next().is_some() {
        return Err(RetirementError::Schema);
    }
    Ok((cycle, nonce, revision))
}

pub(super) fn fence_key(pointer: &RecordPointer, cycle: u64) -> Result<(), RetirementError> {
    let mut parts = pointer.key.split('/');
    if parts.next() != Some("gc")
        || decimal(parts.next().ok_or(RetirementError::Schema)?)? != cycle
        || parts.next() != Some("fence")
    {
        return Err(RetirementError::Schema);
    }
    decimal(parts.next().ok_or(RetirementError::Schema)?)?;
    if parts.next().is_some() {
        return Err(RetirementError::Schema);
    }
    Ok(())
}

fn settings(grace: u64, deletion: u64) -> Result<(u64, u64), RetirementError> {
    if grace == 0 || deletion < grace {
        return Err(RetirementError::Contradiction);
    }
    let grace = grace
        .checked_mul(1_000_000_000)
        .ok_or(RetirementError::Exhausted)?;
    let deletion = deletion
        .checked_mul(1_000_000_000)
        .ok_or(RetirementError::Exhausted)?;
    Ok((grace, deletion))
}

fn waits(
    grace: u64,
    deletion: u64,
    grace_elapsed: u64,
    deletion_elapsed: u64,
) -> Result<(), RetirementError> {
    let (grace_required, deletion_required) = settings(grace, deletion)?;
    if grace_elapsed < grace_required || deletion_elapsed < deletion_required {
        return Err(RetirementError::Contradiction);
    }
    Ok(())
}

fn tombstone(
    bytes: &[u8],
    exclusion: &Exclusion,
    copied: bool,
) -> Result<Tombstone, RetirementError> {
    if bytes.is_empty() || bytes.len() > 128 {
        return Err(RetirementError::Schema);
    }
    let tombstone = Tombstone::decode(bytes)?;
    if tombstone.pack_id != exclusion.pack
        || tombstone.cycle != exclusion.cycle
        || tombstone.epoch != exclusion.epoch
        || copied && tombstone.removed_entries != 0
    {
        return Err(RetirementError::Contradiction);
    }
    Ok(tombstone)
}

fn lease_exclusion(lease: &GcLease, exclusion: &Exclusion) -> Result<(), RetirementError> {
    lease.encode()?;
    if lease.epoch != exclusion.epoch {
        return Err(RetirementError::Contradiction);
    }
    Ok(())
}

fn pack_key(pack: &[u8; 16], index: bool) -> String {
    let id = pack
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "objects/pack/{}/{id}.{}",
        &id[..2],
        if index { "idx" } else { "pack" }
    )
}

fn trash_key(exclusion: &Exclusion) -> String {
    let pack = exclusion
        .pack
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("trash/{}/{pack}", exclusion.cycle)
}

fn remote_barrier(
    artifact: &RemoteArtifact,
    exclusion: &Exclusion,
    bytes: &[u8],
) -> Result<(), RetirementError> {
    if artifact.key != trash_key(exclusion)
        || artifact.digest != *blake3::hash(bytes).as_bytes()
        || artifact.size != u64::try_from(bytes.len()).map_err(|_| RetirementError::Exhausted)?
    {
        return Err(RetirementError::Contradiction);
    }
    Ok(())
}

pub(super) fn plan(value: &CopiedRetirementPlan) -> Result<(), RetirementError> {
    value.backend.encode()?;
    lease_exclusion(&value.lease, &value.exclusion)?;
    tombstone(&value.tombstone, &value.exclusion, true)?;
    fence_key(&value.fence, value.exclusion.cycle)?;
    settings(value.grace_seconds, value.deletion_seconds)?;
    if value.genesis.revision != 0 {
        return Err(RetirementError::Contradiction);
    }
    Ok(())
}

pub(super) fn authorization(value: &PermanentDeleteAuthorization) -> Result<(), RetirementError> {
    match value {
        PermanentDeleteAuthorization::Sweep(value) => {
            value.backend.encode()?;
            if !matches!(value.backend, BackendBinding::Remote { .. }) {
                return Err(RetirementError::Schema);
            }
            lease_exclusion(&value.lease, &value.exclusion)?;
            let trash = tombstone(&value.tombstone, &value.exclusion, false)?;
            waits(
                value.grace_seconds,
                value.deletion_seconds,
                value.grace_elapsed_nanos,
                value.deletion_elapsed_nanos,
            )?;
            fence_key(&value.fence, value.exclusion.cycle)?;
            if value.witness.len() > MAX_RECORD_BYTES {
                return Err(crate::cbor::Error::Limit.into());
            }
            let (header, records) = crate::pack_format::decode_detached_index(&value.witness)?;
            let index_identity = crate::identity::TERRANE_V1
                .calculate(crate::identity::IdentityKind::Index, &value.witness)
                .map_err(|_| RetirementError::Schema)?;
            let index = &value.artifacts[1];
            let pack = &value.artifacts[0];
            if *header.id() != value.exclusion.pack
                || index.digest.as_slice() != index_identity.digest()
                || index.size
                    != u64::try_from(value.witness.len()).map_err(|_| RetirementError::Exhausted)?
                || trash.removed_entries
                    > u64::try_from(records.len()).map_err(|_| RetirementError::Exhausted)?
                || pack.key != pack_key(&value.exclusion.pack, false)
                || index.key != pack_key(&value.exclusion.pack, true)
            {
                return Err(RetirementError::Contradiction);
            }

            // The detached witness includes its own pack header; only its TRIX
            // portion and the footer occupy the pack's trailing index region.
            let trailing_size = index
                .size
                .checked_sub(crate::pack_format::HEADER_SIZE as u64)
                .and_then(|size| size.checked_add(crate::pack_format::FOOTER_SIZE as u64))
                .ok_or(RetirementError::Exhausted)?;
            let body_end = pack
                .size
                .checked_sub(trailing_size)
                .ok_or(RetirementError::Contradiction)?;
            if body_end < crate::pack_format::HEADER_SIZE as u64 {
                return Err(RetirementError::Contradiction);
            }
            for record in records {
                let end = record
                    .offset
                    .checked_add(u64::from(record.body_len))
                    .ok_or(RetirementError::Exhausted)?;
                if end > body_end {
                    return Err(RetirementError::Contradiction);
                }
            }
            remote_barrier(&value.artifacts[2], &value.exclusion, &value.tombstone)?;
        }
        PermanentDeleteAuthorization::Copied(value) => {
            value.backend.encode()?;
            lease_exclusion(&value.lease, &value.exclusion)?;
            tombstone(&value.tombstone, &value.exclusion, true)?;
            waits(
                value.grace_seconds,
                value.deletion_seconds,
                value.grace_elapsed_nanos,
                value.deletion_elapsed_nanos,
            )?;
            // Final current checkpoints may outlive the preparation's root
            // snapshot without replacing its immutable barrier or wait evidence.
            let (_, predecessor_revision) = fence::fence_pointer(&value.fence)?;
            if value.genesis.revision != 0
                || value.preparation.revision <= value.genesis.revision
                || value.preparation.revision > predecessor_revision
            {
                return Err(RetirementError::Contradiction);
            }
            if let Some(fence) = &value.lineage_fence {
                fence::fence_pointer(fence)?;
            }
            match (&value.backend, &value.barrier) {
                (BackendBinding::Remote { .. }, BarrierArtifact::Remote(artifact)) => {
                    remote_barrier(artifact, &value.exclusion, &value.tombstone)?
                }
                (BackendBinding::Local { .. }, BarrierArtifact::Local(artifact)) => {
                    if artifact.key != trash_key(&value.exclusion)
                        || artifact.tombstone != value.tombstone
                        || artifact.file_identity.is_empty()
                        || artifact.file_identity.len() > 128
                    {
                        return Err(RetirementError::Contradiction);
                    }
                }
                _ => return Err(RetirementError::Schema),
            }
        }
    }
    Ok(())
}

pub(super) fn burn_owner(value: &PermanentBurnOwner) -> Result<(), RetirementError> {
    if let PermanentOwnerSelection::Permanent(pointer) = &value.selection
        && operation_key(&pointer.key)?.1 != value.pack
    {
        return Err(RetirementError::Contradiction);
    }
    Ok(())
}

pub(super) fn operation(value: &PermanentDeleteOperation) -> Result<(), RetirementError> {
    authorization(&value.authorization)?;
    match (&value.phase, &value.owner, &value.pass) {
        (OperationPhase::Owned, Some(owner), Some(pointer)) => {
            value.authorization.check_owner_slot(owner)?;
            let (cycle, _, revision) = pass_key(&pointer.key)?;
            if value.revision == 0
                || cycle != value.authorization.exclusion().cycle
                || revision != value.revision
            {
                return Err(RetirementError::Contradiction);
            }
        }
        (OperationPhase::Proposed | OperationPhase::Cancelled, None, None) => {}
        _ => return Err(RetirementError::Contradiction),
    }
    Ok(())
}

pub(super) fn pass(value: &PermanentDeletePass) -> Result<(), RetirementError> {
    value.state.encode()?;
    value.backend.encode()?;
    value.lease.encode()?;
    if value.state.binding != value.backend
        || value.state.revision != value.predecessor.revision
        || value.owner.revision > value.predecessor.revision
        || value.revision == 0
        || value.observations.len() > MAX_OBSERVATIONS
    {
        return Err(RetirementError::Contradiction);
    }
    if matches!(value.backend, BackendBinding::Local { .. }) && value.placement_fence.is_none() {
        return Err(RetirementError::Contradiction);
    }
    if let Some(fence) = &value.placement_fence {
        fence::fence_pointer(fence)?;
    }

    let mut previous = None;
    for row in &value.observations {
        let current = (row.artifact, &row.instance);
        if previous.is_some_and(|prior| prior >= current) {
            return Err(RetirementError::Schema);
        }
        previous = Some(current);
        if let ObservedInstance::Version(handle) | ObservedInstance::Marker(handle) = &row.instance
            && (handle.is_empty()
                || handle.len() > 4096
                || matches!(value.backend, BackendBinding::Local { .. }))
        {
            return Err(RetirementError::Schema);
        }
    }
    if value.phase == PassPhase::PassCompleted
        && (value
            .observations
            .iter()
            .any(|row| row.state == ObservationState::Planned)
            || value.coverage.contains(&PassCoverage::Unknown))
    {
        return Err(RetirementError::Contradiction);
    }
    Ok(())
}
