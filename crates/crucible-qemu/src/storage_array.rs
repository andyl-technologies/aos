//! Deterministic logical-to-member storage-array mapping and parity math.
//!
//! This module contains no guest transport or QEMU state. It turns one exact
//! logical range into member reads and writes using the resolved World policy,
//! including reconstruction of degraded single- and dual-parity stripes.

use std::collections::BTreeMap;

use crucible::model::{ContentHash, WorldStorageArrayLayout};
use thiserror::Error;

use crate::ResolvedStorageArrayPolicy;

/// One exact physical member mutation produced by an array write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageArrayMemberWrite {
    /// Immutable content identity of the backing block device.
    pub device: ContentHash,
    /// Stable member ordinal used by the array layout.
    pub ordinal: u16,
    /// First physical byte changed on the member.
    pub offset: u64,
    /// Exact replacement bytes.
    pub bytes: Vec<u8>,
}

/// Result of planning one logical array write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageArrayWritePlan {
    /// Canonically device/offset-ordered physical writes to online members.
    pub writes: Vec<StorageArrayMemberWrite>,
    /// Canonically member/offset-ordered physical writes owed to offline members.
    pub dirty_writes: Vec<StorageArrayMemberWrite>,
}

/// A storage-array mapping, quorum, or reconstruction failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StorageArrayError {
    /// The resolved member table is not a complete ordinal sequence.
    #[error("storage array members must have unique contiguous ordinals starting at zero")]
    InvalidMemberOrdinals,
    /// The layout does not have enough members to store data and parity.
    #[error("storage array layout requires more members")]
    InsufficientMembers,
    /// The logical request range cannot be represented by the layout.
    #[error("storage array request range or stripe geometry overflows")]
    RangeOverflow,
    /// A member read returned a different byte count than requested.
    #[error("storage array member {ordinal} returned {actual} bytes; expected {expected}")]
    ShortMemberRead {
        /// Member whose read violated the exact range contract.
        ordinal: u16,
        /// Required byte count.
        expected: usize,
        /// Returned byte count.
        actual: usize,
    },
    /// A member read failed at the authoritative device.
    #[error("storage array member {ordinal} read failed: {message}")]
    MemberRead {
        /// Member whose read failed.
        ordinal: u16,
        /// Adapter error text.
        message: String,
    },
    /// The current online set cannot satisfy the operation.
    #[error("storage array has no reconstructable quorum")]
    QuorumUnavailable,
}

/// Reads one logical range through the selected array layout.
///
/// `read_member` must return exact controller-visible bytes from the identified
/// backing device. Mirror selection is deterministic: lowest ordinal, stable
/// request hash, or least outstanding load with ordinal tie breaking.
///
/// # Errors
///
/// Returns [`StorageArrayError`] when geometry overflows, a selected member read
/// fails, or the available fragments cannot reconstruct the requested bytes.
pub fn read_storage_array(
    policy: &ResolvedStorageArrayPolicy,
    offset: u64,
    count: u32,
    request_key: &[u8],
    outstanding: &BTreeMap<u16, u64>,
    // crucible-lint: allow stringly-error -- heterogeneous member transports are folded immediately into typed StorageArrayError context.
    mut read_member: impl FnMut(ContentHash, u64, u32) -> Result<Vec<u8>, String>,
) -> Result<Vec<u8>, StorageArrayError> {
    let members = ordered_members(policy)?;
    if members.iter().filter(|member| member.online).count() < usize::from(policy.read_quorum) {
        return Err(StorageArrayError::QuorumUnavailable);
    }
    let chunk_bytes = usize::try_from(policy.chunk_bytes)
        .ok()
        .filter(|chunk| *chunk != 0 && *chunk <= u32::MAX as usize)
        .ok_or(StorageArrayError::RangeOverflow)?;
    let end = offset
        .checked_add(u64::from(count))
        .ok_or(StorageArrayError::RangeOverflow)?;
    let mut cursor = offset;
    let mut result = Vec::with_capacity(count as usize);
    while cursor < end {
        match policy.layout {
            WorldStorageArrayLayout::Mirror => {
                let selected =
                    select_mirror_member(policy, &members, request_key, cursor, outstanding)?;
                let within = usize::try_from(cursor % policy.chunk_bytes)
                    .map_err(|_| StorageArrayError::RangeOverflow)?;
                let take = (end - cursor).min((chunk_bytes - within) as u64);
                let bytes = exact_read(
                    selected.ordinal,
                    selected.device,
                    cursor,
                    u32::try_from(take).map_err(|_| StorageArrayError::RangeOverflow)?,
                    &mut read_member,
                )?;
                result.extend(bytes);
                cursor = cursor
                    .checked_add(take)
                    .ok_or(StorageArrayError::RangeOverflow)?;
            }
            layout => {
                let data_members = data_member_count(layout, members.len())?;
                let logical_chunk = cursor / policy.chunk_bytes;
                let stripe = logical_chunk / data_members as u64;
                let data_index = usize::try_from(logical_chunk % data_members as u64)
                    .map_err(|_| StorageArrayError::RangeOverflow)?;
                let within = usize::try_from(cursor % policy.chunk_bytes)
                    .map_err(|_| StorageArrayError::RangeOverflow)?;
                let take = (end - cursor).min((chunk_bytes - within) as u64);
                let chunks = load_stripe(policy, &members, stripe, chunk_bytes, &mut read_member)?;
                let geometry = stripe_geometry(layout, members.len(), stripe)?;
                result.extend_from_slice(
                    &chunks[geometry.data_ordinals[data_index]][within..within + take as usize],
                );
                cursor = cursor
                    .checked_add(take)
                    .ok_or(StorageArrayError::RangeOverflow)?;
            }
        }
    }
    Ok(result)
}

/// Plans one logical write against exact currently visible member bytes.
///
/// Parity layouts reconstruct complete touched stripes first, apply the logical
/// byte changes, and then recompute P and Q from the resulting data. This avoids
/// read-modify-write ambiguity when an old data or parity fragment is offline.
/// Offline fragments are returned as exact `dirty_writes`; callers persist
/// those physical member mutations until bounded rebuild repairs them.
///
/// # Errors
///
/// Returns [`StorageArrayError`] when geometry overflows, write quorum is absent,
/// atomic-stripe policy encounters an offline member, or a touched stripe cannot
/// be reconstructed.
pub fn plan_storage_array_write(
    policy: &ResolvedStorageArrayPolicy,
    offset: u64,
    bytes: &[u8],
    // crucible-lint: allow stringly-error -- heterogeneous member transports are folded immediately into typed StorageArrayError context.
    mut read_member: impl FnMut(ContentHash, u64, u32) -> Result<Vec<u8>, String>,
) -> Result<StorageArrayWritePlan, StorageArrayError> {
    let members = ordered_members(policy)?;
    let online = members.iter().filter(|member| member.online).count();
    if online < usize::from(policy.write_quorum)
        || (matches!(
            policy.consistency,
            crucible::model::StoragePolicyArrayConsistency::AtomicStripe
        ) && online != members.len())
    {
        return Err(StorageArrayError::QuorumUnavailable);
    }
    let chunk_bytes = usize::try_from(policy.chunk_bytes)
        .ok()
        .filter(|chunk| *chunk != 0 && *chunk <= u32::MAX as usize)
        .ok_or(StorageArrayError::RangeOverflow)?;
    let end = offset
        .checked_add(u64::try_from(bytes.len()).map_err(|_| StorageArrayError::RangeOverflow)?)
        .ok_or(StorageArrayError::RangeOverflow)?;
    let mut writes = Vec::new();
    let mut dirty_writes = Vec::new();
    match policy.layout {
        WorldStorageArrayLayout::Mirror => {
            for member in &members {
                let write = StorageArrayMemberWrite {
                    device: member.device,
                    ordinal: member.ordinal,
                    offset,
                    bytes: bytes.to_vec(),
                };
                if member.online {
                    writes.push(write);
                } else {
                    dirty_writes.push(write);
                }
            }
        }
        WorldStorageArrayLayout::Stripe => {
            let mut cursor = offset;
            let mut source = 0_usize;
            while cursor < end {
                let logical_chunk = cursor / policy.chunk_bytes;
                let member_index = usize::try_from(logical_chunk % members.len() as u64)
                    .map_err(|_| StorageArrayError::RangeOverflow)?;
                let member = &members[member_index];
                if !member.online {
                    return Err(StorageArrayError::QuorumUnavailable);
                }
                let stripe = logical_chunk / members.len() as u64;
                let within = usize::try_from(cursor % policy.chunk_bytes)
                    .map_err(|_| StorageArrayError::RangeOverflow)?;
                let take = (end - cursor).min((chunk_bytes - within) as u64) as usize;
                let physical = stripe
                    .checked_mul(policy.chunk_bytes)
                    .and_then(|base| base.checked_add(within as u64))
                    .ok_or(StorageArrayError::RangeOverflow)?;
                writes.push(StorageArrayMemberWrite {
                    device: member.device,
                    ordinal: member.ordinal,
                    offset: physical,
                    bytes: bytes[source..source + take].to_vec(),
                });
                cursor += take as u64;
                source += take;
            }
        }
        layout @ (WorldStorageArrayLayout::SingleParity | WorldStorageArrayLayout::DualParity) => {
            let data_members = data_member_count(layout, members.len())?;
            let first_chunk = offset / policy.chunk_bytes;
            let last_chunk = end.saturating_sub(1) / policy.chunk_bytes;
            let first_stripe = first_chunk / data_members as u64;
            let last_stripe = last_chunk / data_members as u64;
            let mut source = 0_usize;
            for stripe in first_stripe..=last_stripe {
                let geometry = stripe_geometry(layout, members.len(), stripe)?;
                let mut chunks =
                    load_stripe(policy, &members, stripe, chunk_bytes, &mut read_member)?;
                for (data_index, ordinal) in geometry.data_ordinals.iter().copied().enumerate() {
                    let logical_chunk = stripe
                        .checked_mul(data_members as u64)
                        .and_then(|base| base.checked_add(data_index as u64))
                        .ok_or(StorageArrayError::RangeOverflow)?;
                    let logical_start = logical_chunk
                        .checked_mul(policy.chunk_bytes)
                        .ok_or(StorageArrayError::RangeOverflow)?;
                    let logical_end = logical_start
                        .checked_add(policy.chunk_bytes)
                        .ok_or(StorageArrayError::RangeOverflow)?;
                    let overlap_start = offset.max(logical_start);
                    let overlap_end = end.min(logical_end);
                    if overlap_start >= overlap_end {
                        continue;
                    }
                    let destination_start = usize::try_from(overlap_start - logical_start)
                        .map_err(|_| StorageArrayError::RangeOverflow)?;
                    let length = usize::try_from(overlap_end - overlap_start)
                        .map_err(|_| StorageArrayError::RangeOverflow)?;
                    chunks[ordinal][destination_start..destination_start + length]
                        .copy_from_slice(&bytes[source..source + length]);
                    source += length;
                }
                recompute_parity(&mut chunks, &geometry);
                let physical = stripe
                    .checked_mul(policy.chunk_bytes)
                    .ok_or(StorageArrayError::RangeOverflow)?;
                for (ordinal, member) in members.iter().enumerate() {
                    let write = StorageArrayMemberWrite {
                        device: member.device,
                        ordinal: member.ordinal,
                        offset: physical,
                        bytes: chunks[ordinal].clone(),
                    };
                    if member.online {
                        writes.push(write);
                    } else {
                        dirty_writes.push(write);
                    }
                }
            }
        }
    }
    writes.sort_by(|left, right| {
        left.device
            .cmp(&right.device)
            .then(left.offset.cmp(&right.offset))
    });
    dirty_writes.sort_by(|left, right| {
        left.ordinal
            .cmp(&right.ordinal)
            .then(left.offset.cmp(&right.offset))
    });
    Ok(StorageArrayWritePlan {
        writes,
        dirty_writes,
    })
}

#[derive(Clone, Debug)]
struct StripeGeometry {
    data_ordinals: Vec<usize>,
    p_ordinal: Option<usize>,
    q_ordinal: Option<usize>,
}

fn ordered_members(
    policy: &ResolvedStorageArrayPolicy,
) -> Result<Vec<&crate::ResolvedStorageArrayMember>, StorageArrayError> {
    let mut members = policy.members.iter().collect::<Vec<_>>();
    members.sort_by_key(|member| member.ordinal);
    if members
        .iter()
        .enumerate()
        .any(|(index, member)| usize::from(member.ordinal) != index)
    {
        return Err(StorageArrayError::InvalidMemberOrdinals);
    }
    data_member_count(policy.layout, members.len())?;
    Ok(members)
}

fn data_member_count(
    layout: WorldStorageArrayLayout,
    members: usize,
) -> Result<usize, StorageArrayError> {
    let parity = match layout {
        WorldStorageArrayLayout::Mirror => 0,
        WorldStorageArrayLayout::Stripe => 0,
        WorldStorageArrayLayout::SingleParity => 1,
        WorldStorageArrayLayout::DualParity => 2,
    };
    let minimum = match layout {
        WorldStorageArrayLayout::Mirror => 1,
        WorldStorageArrayLayout::Stripe => 1,
        WorldStorageArrayLayout::SingleParity => 3,
        WorldStorageArrayLayout::DualParity => 4,
    };
    if members < minimum {
        return Err(StorageArrayError::InsufficientMembers);
    }
    Ok(members - parity)
}

fn stripe_geometry(
    layout: WorldStorageArrayLayout,
    members: usize,
    stripe: u64,
) -> Result<StripeGeometry, StorageArrayError> {
    data_member_count(layout, members)?;
    let (p_ordinal, q_ordinal) = match layout {
        WorldStorageArrayLayout::SingleParity => {
            (Some(members - 1 - stripe as usize % members), None)
        }
        WorldStorageArrayLayout::DualParity => {
            let p = members - 1 - stripe as usize % members;
            let q = members - 1 - (stripe as usize + 1) % members;
            (Some(p), Some(q))
        }
        _ => (None, None),
    };
    let data_ordinals = (0..members)
        .filter(|ordinal| Some(*ordinal) != p_ordinal && Some(*ordinal) != q_ordinal)
        .collect();
    Ok(StripeGeometry {
        data_ordinals,
        p_ordinal,
        q_ordinal,
    })
}

fn load_stripe(
    policy: &ResolvedStorageArrayPolicy,
    members: &[&crate::ResolvedStorageArrayMember],
    stripe: u64,
    chunk_bytes: usize,
    // crucible-lint: allow stringly-error -- the private callback seam folds member diagnostics into typed StorageArrayError context.
    read_member: &mut impl FnMut(ContentHash, u64, u32) -> Result<Vec<u8>, String>,
) -> Result<Vec<Vec<u8>>, StorageArrayError> {
    let physical = stripe
        .checked_mul(policy.chunk_bytes)
        .ok_or(StorageArrayError::RangeOverflow)?;
    let count = u32::try_from(chunk_bytes).map_err(|_| StorageArrayError::RangeOverflow)?;
    let mut chunks = members
        .iter()
        .map(|member| {
            if member.online {
                exact_read(member.ordinal, member.device, physical, count, read_member).map(Some)
            } else {
                Ok(None)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let geometry = stripe_geometry(policy.layout, members.len(), stripe)?;
    reconstruct_missing(&mut chunks, &geometry, chunk_bytes)?;
    chunks
        .into_iter()
        .map(|chunk| chunk.ok_or(StorageArrayError::QuorumUnavailable))
        .collect()
}

fn reconstruct_missing(
    chunks: &mut [Option<Vec<u8>>],
    geometry: &StripeGeometry,
    chunk_bytes: usize,
) -> Result<(), StorageArrayError> {
    let missing = chunks
        .iter()
        .enumerate()
        .filter_map(|(ordinal, chunk)| chunk.is_none().then_some(ordinal))
        .collect::<Vec<_>>();
    let parity_count =
        usize::from(geometry.p_ordinal.is_some()) + usize::from(geometry.q_ordinal.is_some());
    if missing.len() > parity_count {
        return Err(StorageArrayError::QuorumUnavailable);
    }
    if missing.is_empty() {
        return Ok(());
    }
    let missing_data = missing
        .iter()
        .copied()
        .filter(|ordinal| geometry.data_ordinals.contains(ordinal))
        .collect::<Vec<_>>();
    if missing_data.len() == 1 {
        let ordinal = missing_data[0];
        let data_index = geometry
            .data_ordinals
            .iter()
            .position(|candidate| *candidate == ordinal)
            .ok_or(StorageArrayError::QuorumUnavailable)?;
        let recovered = if let Some(p) = geometry.p_ordinal.filter(|p| chunks[*p].is_some()) {
            let mut value = chunks[p]
                .as_ref()
                .ok_or(StorageArrayError::QuorumUnavailable)?
                .clone();
            for other in geometry
                .data_ordinals
                .iter()
                .copied()
                .filter(|other| *other != ordinal)
            {
                xor_into(
                    &mut value,
                    chunks[other]
                        .as_ref()
                        .ok_or(StorageArrayError::QuorumUnavailable)?,
                );
            }
            value
        } else {
            let q = geometry
                .q_ordinal
                .filter(|q| chunks[*q].is_some())
                .ok_or(StorageArrayError::QuorumUnavailable)?;
            let mut value = chunks[q]
                .as_ref()
                .ok_or(StorageArrayError::QuorumUnavailable)?
                .clone();
            for (other_index, other) in geometry.data_ordinals.iter().copied().enumerate() {
                if other != ordinal {
                    xor_mul_into(
                        &mut value,
                        chunks[other]
                            .as_ref()
                            .ok_or(StorageArrayError::QuorumUnavailable)?,
                        gf_coefficient(other_index),
                    );
                }
            }
            let inverse = gf_inverse(gf_coefficient(data_index));
            for byte in &mut value {
                *byte = gf_mul(*byte, inverse);
            }
            value
        };
        chunks[ordinal] = Some(recovered);
    } else if missing_data.len() == 2 {
        let p = geometry
            .p_ordinal
            .and_then(|ordinal| chunks[ordinal].as_ref())
            .ok_or(StorageArrayError::QuorumUnavailable)?;
        let q = geometry
            .q_ordinal
            .and_then(|ordinal| chunks[ordinal].as_ref())
            .ok_or(StorageArrayError::QuorumUnavailable)?;
        let first = missing_data[0];
        let second = missing_data[1];
        let first_index = geometry
            .data_ordinals
            .iter()
            .position(|ordinal| *ordinal == first)
            .ok_or(StorageArrayError::QuorumUnavailable)?;
        let second_index = geometry
            .data_ordinals
            .iter()
            .position(|ordinal| *ordinal == second)
            .ok_or(StorageArrayError::QuorumUnavailable)?;
        let mut p_delta = p.clone();
        let mut q_delta = q.clone();
        for (data_index, ordinal) in geometry.data_ordinals.iter().copied().enumerate() {
            if ordinal != first && ordinal != second {
                let data = chunks[ordinal]
                    .as_ref()
                    .ok_or(StorageArrayError::QuorumUnavailable)?;
                xor_into(&mut p_delta, data);
                xor_mul_into(&mut q_delta, data, gf_coefficient(data_index));
            }
        }
        let first_coefficient = gf_coefficient(first_index);
        let second_coefficient = gf_coefficient(second_index);
        let inverse = gf_inverse(first_coefficient ^ second_coefficient);
        let mut first_data = vec![0_u8; chunk_bytes];
        let mut second_data = vec![0_u8; chunk_bytes];
        for index in 0..chunk_bytes {
            first_data[index] = gf_mul(
                q_delta[index] ^ gf_mul(second_coefficient, p_delta[index]),
                inverse,
            );
            second_data[index] = p_delta[index] ^ first_data[index];
        }
        chunks[first] = Some(first_data);
        chunks[second] = Some(second_data);
    }
    let mut complete = chunks
        .iter()
        .map(|chunk| chunk.clone().unwrap_or_else(|| vec![0; chunk_bytes]))
        .collect::<Vec<_>>();
    recompute_parity(&mut complete, geometry);
    if let Some(p) = geometry.p_ordinal
        && chunks[p].is_none()
    {
        chunks[p] = Some(complete[p].clone());
    }
    if let Some(q) = geometry.q_ordinal
        && chunks[q].is_none()
    {
        chunks[q] = Some(complete[q].clone());
    }
    Ok(())
}

fn recompute_parity(chunks: &mut [Vec<u8>], geometry: &StripeGeometry) {
    if let Some(p) = geometry.p_ordinal {
        chunks[p].fill(0);
        for ordinal in &geometry.data_ordinals {
            for index in 0..chunks[p].len() {
                chunks[p][index] ^= chunks[*ordinal][index];
            }
        }
    }
    if let Some(q) = geometry.q_ordinal {
        chunks[q].fill(0);
        for (data_index, ordinal) in geometry.data_ordinals.iter().copied().enumerate() {
            let coefficient = gf_coefficient(data_index);
            for index in 0..chunks[q].len() {
                chunks[q][index] ^= gf_mul(chunks[ordinal][index], coefficient);
            }
        }
    }
}

fn select_mirror_member<'a>(
    policy: &ResolvedStorageArrayPolicy,
    members: &'a [&crate::ResolvedStorageArrayMember],
    request_key: &[u8],
    offset: u64,
    outstanding: &BTreeMap<u16, u64>,
) -> Result<&'a crate::ResolvedStorageArrayMember, StorageArrayError> {
    let online = members
        .iter()
        .copied()
        .filter(|member| member.online)
        .collect::<Vec<_>>();
    if online.len() < usize::from(policy.read_quorum) {
        return Err(StorageArrayError::QuorumUnavailable);
    }
    match policy.selection {
        crucible::model::StoragePolicyArraySelection::LowestHealthy => online
            .first()
            .copied()
            .ok_or(StorageArrayError::QuorumUnavailable),
        crucible::model::StoragePolicyArraySelection::StableHash => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"crucible.storage-array-selection.v1\0");
            hasher.update(request_key);
            hasher.update(&offset.to_le_bytes());
            let mut index = [0_u8; 8];
            index.copy_from_slice(&hasher.finalize().as_bytes()[..8]);
            Ok(online[u64::from_le_bytes(index) as usize % online.len()])
        }
        crucible::model::StoragePolicyArraySelection::LeastLoaded => online
            .into_iter()
            .min_by_key(|member| {
                (
                    outstanding.get(&member.ordinal).copied().unwrap_or(0),
                    member.ordinal,
                )
            })
            .ok_or(StorageArrayError::QuorumUnavailable),
    }
}

fn exact_read(
    ordinal: u16,
    device: ContentHash,
    offset: u64,
    count: u32,
    // crucible-lint: allow stringly-error -- the private callback seam folds member diagnostics into typed StorageArrayError context.
    read_member: &mut impl FnMut(ContentHash, u64, u32) -> Result<Vec<u8>, String>,
) -> Result<Vec<u8>, StorageArrayError> {
    let bytes = read_member(device, offset, count)
        .map_err(|message| StorageArrayError::MemberRead { ordinal, message })?;
    let expected = count as usize;
    if bytes.len() != expected {
        return Err(StorageArrayError::ShortMemberRead {
            ordinal,
            expected,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

fn xor_into(destination: &mut [u8], source: &[u8]) {
    for (destination, source) in destination.iter_mut().zip(source) {
        *destination ^= *source;
    }
}

fn xor_mul_into(destination: &mut [u8], source: &[u8], coefficient: u8) {
    for (destination, source) in destination.iter_mut().zip(source) {
        *destination ^= gf_mul(*source, coefficient);
    }
}

fn gf_coefficient(data_index: usize) -> u8 {
    let mut value = 1_u8;
    for _ in 0..data_index {
        value = gf_mul(value, 2);
    }
    value
}

fn gf_inverse(value: u8) -> u8 {
    let mut result = 1_u8;
    for _ in 0..254 {
        result = gf_mul(result, value);
    }
    result
}

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0_u8;
    while right != 0 {
        if right & 1 != 0 {
            result ^= left;
        }
        let high = left & 0x80;
        left <<= 1;
        if high != 0 {
            left ^= 0x1d;
        }
        right >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_parity_recovers_two_missing_data_chunks() {
        let geometry = stripe_geometry(WorldStorageArrayLayout::DualParity, 5, 0)
            .unwrap_or_else(|error| panic!("build geometry: {error}"));
        let mut complete = vec![vec![0_u8; 8]; 5];
        for (index, ordinal) in geometry.data_ordinals.iter().copied().enumerate() {
            complete[ordinal].fill((index + 1) as u8);
        }
        recompute_parity(&mut complete, &geometry);
        let mut degraded = complete.iter().cloned().map(Some).collect::<Vec<_>>();
        degraded[geometry.data_ordinals[0]] = None;
        degraded[geometry.data_ordinals[2]] = None;
        reconstruct_missing(&mut degraded, &geometry, 8)
            .unwrap_or_else(|error| panic!("reconstruct stripe: {error}"));
        assert_eq!(
            degraded
                .into_iter()
                .map(|chunk| chunk.unwrap_or_else(|| panic!("chunk restored")))
                .collect::<Vec<_>>(),
            complete
        );
    }

    #[test]
    fn rotating_parity_never_overlaps_data() {
        for stripe in 0..16 {
            let geometry = stripe_geometry(WorldStorageArrayLayout::DualParity, 6, stripe)
                .unwrap_or_else(|error| panic!("build geometry: {error}"));
            assert_ne!(geometry.p_ordinal, geometry.q_ordinal);
            assert_eq!(geometry.data_ordinals.len(), 4);
            assert!(
                geometry
                    .data_ordinals
                    .iter()
                    .all(|ordinal| Some(*ordinal) != geometry.p_ordinal
                        && Some(*ordinal) != geometry.q_ordinal)
            );
        }
    }
}
