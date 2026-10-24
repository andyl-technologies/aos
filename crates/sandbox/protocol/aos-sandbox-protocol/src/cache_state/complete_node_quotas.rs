//! Shares the complete node-quota envelope and its existing V2 commitment.
//!
//! ```text
//! node[16] | count:u32be | sorted rows[count]
//! row = partition-digest[32] | nine quota values:u64be
//! values = physical bytes, resident objects, logical pins, source retentions,
//!          kernel references, backing registrations, recovery bytes,
//!          high-water bytes, low-water bytes
//! ```
//!
//! These rows carry all limits, rather than only their digest. Received rows
//! remain comparison DATA: a Root consumer must compare them with its own
//! validated complete Cache selection. They supply no native partition object,
//! currentness, budget or mutation authority.

use aos_sandbox_model::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::NodeCacheQuotaV1;

/// Retains the existing complete-manifest ceiling for one node's quota set.
pub const MAXIMUM_COMPLETE_NODE_QUOTAS_V1: usize = 4_096;

/// Gives the exact fixed width of one complete quota comparison row.
pub const COMPLETE_NODE_QUOTA_ROW_BYTES_V1: usize = 104;

const HEADER_BYTES: usize = 20;
const DOMAIN_V2: &[u8] = b"aos.sandbox.cache.complete-node-quota-envelope.v2\0";

/// Reports invalid quota input or unrepresentable exact framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CompleteNodeQuotaDataErrorV1 {
    /// Typed limits, node association or strict partition ordering are invalid.
    #[error("invalid complete node-quota data")]
    Invalid,
    /// A count, fixed extent or destination width does not match.
    #[error("invalid complete node-quota extent")]
    Extent,
}

/// Borrows all complete quota rows without allocating a model or partition map.
#[derive(Clone, Copy)]
pub struct CompleteNodeQuotaRowsDataV1<'bytes> {
    node: [u8; 16],
    count: usize,
    rows: &'bytes [u8],
}

impl<'bytes> CompleteNodeQuotaRowsDataV1<'bytes> {
    /// Borrows exact row framing and verifies strict partition-digest ordering.
    ///
    /// Numeric limits remain untrusted DATA. A receiving consumer compares
    /// every exact row with its separately validated current Cache quota model.
    ///
    /// # Errors
    /// Rejects truncation, trailing data, excessive count, invalid node sentinel,
    /// a reserved partition digest or duplicate/nonincreasing partition order.
    pub fn decode(bytes: &'bytes [u8]) -> Result<Self, CompleteNodeQuotaDataErrorV1> {
        let header = bytes.get(..HEADER_BYTES).ok_or(CompleteNodeQuotaDataErrorV1::Extent)?;
        let node = header[..16].try_into().map_err(|_| CompleteNodeQuotaDataErrorV1::Extent)?;
        let count = u32::from_be_bytes(header[16..].try_into()
            .map_err(|_| CompleteNodeQuotaDataErrorV1::Extent)?);
        let count = usize::try_from(count).map_err(|_| CompleteNodeQuotaDataErrorV1::Extent)?;
        if count > MAXIMUM_COMPLETE_NODE_QUOTAS_V1 || (node == [0; 16]) != (count == 0) {
            return Err(CompleteNodeQuotaDataErrorV1::Invalid);
        }
        let width = encoded_bytes_for_count(count)?;
        if bytes.len() != width {
            return Err(CompleteNodeQuotaDataErrorV1::Extent);
        }
        let rows = &bytes[HEADER_BYTES..];
        let mut previous: Option<&[u8]> = None;
        for row in rows.chunks_exact(COMPLETE_NODE_QUOTA_ROW_BYTES_V1) {
            let partition = &row[..32];
            if partition == [0; 32] || previous.is_some_and(|prior| prior >= partition) {
                return Err(CompleteNodeQuotaDataErrorV1::Invalid);
            }
            previous = Some(partition);
        }
        Ok(Self { node, count, rows })
    }

    /// Returns the comparison node carried by this complete envelope.
    #[must_use]
    pub const fn node(self) -> [u8; 16] { self.node }

    /// Returns every exact partition/limit row in strict digest order.
    ///
    /// Each row is exactly [`COMPLETE_NODE_QUOTA_ROW_BYTES_V1`] bytes. This
    /// borrowed iterator neither parses a native partition nor allocates one.
    pub fn rows(self) -> impl ExactSizeIterator<Item = &'bytes [u8]> {
        self.rows.chunks_exact(COMPLETE_NODE_QUOTA_ROW_BYTES_V1)
    }

    /// Recomputes the unchanged V2 quota commitment over every exact row.
    ///
    /// The original V2 domain commits count and row bytes. Node agreement is
    /// validated separately and is not silently added to that existing domain.
    #[must_use]
    pub fn digest_v2(self) -> ObjectDigest {
        let digest = Sha256::new().chain_update(DOMAIN_V2)
            .chain_update((self.count as u64).to_be_bytes())
            .chain_update(self.rows).finalize();
        ObjectDigest::from_bytes(digest.into())
    }
}

/// Measures the exact complete row encoding from the existing count ceiling.
///
/// # Errors
/// Rejects an excessive count or checked width overflow.
pub fn complete_node_quota_rows_encoded_bytes_v1(count: usize)
    -> Result<usize, CompleteNodeQuotaDataErrorV1>
{
    if count > MAXIMUM_COMPLETE_NODE_QUOTAS_V1 {
        return Err(CompleteNodeQuotaDataErrorV1::Extent);
    }
    encoded_bytes_for_count(count)
}

/// Encodes already-sorted actual typed quotas into prepaid exact storage.
///
/// Sorting belongs to the genuine producer and must be funded before growth.
/// No copy or sorting is performed here. An empty set uses the zero node.
///
/// # Errors
/// Rejects invalid typed limits, mixed nodes, duplicate/nonincreasing partition
/// order, count overflow or a nonexact destination before writing any output.
pub fn encode_complete_node_quota_rows_v1(quotas: &[NodeCacheQuotaV1], output: &mut [u8])
    -> Result<(), CompleteNodeQuotaDataErrorV1>
{
    validate_sorted(quotas)?;
    if output.len() != complete_node_quota_rows_encoded_bytes_v1(quotas.len())? {
        return Err(CompleteNodeQuotaDataErrorV1::Extent);
    }
    let node = quotas.first().map(|quota| *quota.partition.node().as_bytes()).unwrap_or([0; 16]);
    output[..16].copy_from_slice(&node);
    let count = u32::try_from(quotas.len()).map_err(|_| CompleteNodeQuotaDataErrorV1::Extent)?;
    output[16..HEADER_BYTES].copy_from_slice(&count.to_be_bytes());
    for (quota, row) in quotas.iter().zip(output[HEADER_BYTES..]
        .chunks_exact_mut(COMPLETE_NODE_QUOTA_ROW_BYTES_V1)) {
        row.copy_from_slice(&quota_row(*quota));
    }
    Ok(())
}

/// Computes the existing complete V2 commitment from sorted actual typed quotas.
///
/// The native owner retains its original sort and count checks before invoking
/// this sole digest recipe. This function provides comparison DATA only.
///
/// # Errors
/// Rejects invalid typed quota limits, excessive count, mixed nodes or partitions
/// that are not strictly ordered by their complete physical identity digest.
pub fn complete_node_quota_digest_v2(quotas: &[NodeCacheQuotaV1])
    -> Result<ObjectDigest, CompleteNodeQuotaDataErrorV1>
{
    validate_sorted(quotas)?;
    let mut digest = Sha256::new().chain_update(DOMAIN_V2)
        .chain_update((quotas.len() as u64).to_be_bytes());
    for quota in quotas {
        digest = digest.chain_update(quota_row(*quota));
    }
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

fn validate_sorted(quotas: &[NodeCacheQuotaV1]) -> Result<(), CompleteNodeQuotaDataErrorV1> {
    if quotas.len() > MAXIMUM_COMPLETE_NODE_QUOTAS_V1 {
        return Err(CompleteNodeQuotaDataErrorV1::Extent);
    }
    let node = quotas.first().map(|quota| quota.partition.node());
    let mut previous = None;
    for quota in quotas {
        quota.validate().map_err(|_| CompleteNodeQuotaDataErrorV1::Invalid)?;
        let partition = quota.partition.digest();
        if Some(quota.partition.node()) != node
            || previous.is_some_and(|prior| prior >= partition) {
            return Err(CompleteNodeQuotaDataErrorV1::Invalid);
        }
        previous = Some(partition);
    }
    Ok(())
}

fn quota_row(quota: NodeCacheQuotaV1) -> [u8; COMPLETE_NODE_QUOTA_ROW_BYTES_V1] {
    let mut row = [0; COMPLETE_NODE_QUOTA_ROW_BYTES_V1];
    row[..32].copy_from_slice(quota.partition.digest().as_bytes());
    let values = [quota.maximum_physical_bytes, quota.maximum_resident_objects,
        quota.maximum_logical_pins, quota.maximum_source_retentions,
        quota.maximum_kernel_references, quota.maximum_backing_registrations,
        quota.recovery_reserve_bytes, quota.high_water_bytes, quota.low_water_bytes];
    for (value, target) in values.into_iter().zip(row[32..].chunks_exact_mut(8)) {
        target.copy_from_slice(&value.to_be_bytes());
    }
    row
}

fn encoded_bytes_for_count(count: usize) -> Result<usize, CompleteNodeQuotaDataErrorV1> {
    count.checked_mul(COMPLETE_NODE_QUOTA_ROW_BYTES_V1)
        .and_then(|bytes| bytes.checked_add(HEADER_BYTES))
        .ok_or(CompleteNodeQuotaDataErrorV1::Extent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{CacheNodeIdV1, PhysicalPartitionId, ProtectedBackingIdentityV1};
    use aos_sandbox_model::{CacheDomainId, model::{CacheDomain, CacheDomainKind}};

    fn quota(node: u8, policy: u8) -> NodeCacheQuotaV1 {
        let backing = ProtectedBackingIdentityV1::new(ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]), ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32])).unwrap();
        let partition = PhysicalPartitionId::derive(CacheNodeIdV1::from_bytes([node; 16]).unwrap(),
            backing, CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([6; 16])),
            ObjectDigest::from_bytes([policy; 32])).unwrap();
        NodeCacheQuotaV1 {
            partition, maximum_physical_bytes: 1_000, maximum_resident_objects: 11,
            maximum_logical_pins: 12, maximum_source_retentions: 13,
            maximum_kernel_references: 14, maximum_backing_registrations: 15,
            recovery_reserve_bytes: 16, high_water_bytes: 900, low_water_bytes: 800,
        }
    }

    #[test]
    fn all_limits_reproduce_the_existing_v2_golden_commitment() {
        let original = quota(1, 7);
        let mut bytes = vec![0; complete_node_quota_rows_encoded_bytes_v1(1).unwrap()];
        encode_complete_node_quota_rows_v1(&[original], &mut bytes).unwrap();
        let borrowed = CompleteNodeQuotaRowsDataV1::decode(&bytes).unwrap();
        let golden = ObjectDigest::from_bytes([
            214, 32, 101, 29, 19, 208, 125, 10, 254, 21, 97, 2, 80, 120, 150, 89,
            250, 149, 111, 179, 42, 70, 38, 151, 187, 140, 61, 138, 98, 79, 94, 35,
        ]);
        assert_eq!(borrowed.node(), [1; 16]);
        assert_eq!(borrowed.rows().len(), 1);
        assert_eq!(borrowed.digest_v2(), golden);
        assert_eq!(complete_node_quota_digest_v2(&[original]).unwrap(), golden);
        for offset in (20 + 32..bytes.len()).step_by(8) {
            let mut changed = bytes.clone();
            changed[offset + 7] ^= 1;
            assert_ne!(CompleteNodeQuotaRowsDataV1::decode(&changed).unwrap().digest_v2(), golden);
        }
    }

    #[test]
    fn complete_rows_refuse_wrong_counts_order_nodes_and_typed_limits() {
        let mut quotas = vec![quota(1, 7), quota(1, 8)];
        quotas.sort_unstable_by_key(|quota| quota.partition.digest());
        let mut bytes = vec![0; complete_node_quota_rows_encoded_bytes_v1(2).unwrap()];
        encode_complete_node_quota_rows_v1(&quotas, &mut bytes).unwrap();
        for width in 0..bytes.len() {
            assert!(CompleteNodeQuotaRowsDataV1::decode(&bytes[..width]).is_err());
        }
        let mut oversized = bytes.clone();
        oversized[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(CompleteNodeQuotaRowsDataV1::decode(&oversized).is_err());
        assert!(CompleteNodeQuotaRowsDataV1::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
        let first = bytes[20..124].to_vec();
        bytes[124..228].copy_from_slice(&first);
        assert!(CompleteNodeQuotaRowsDataV1::decode(&bytes).is_err());
        assert!(complete_node_quota_digest_v2(&[quotas[0], quotas[0]]).is_err());
        let mut foreign = vec![quotas[0], quota(2, 9)];
        foreign.sort_unstable_by_key(|quota| quota.partition.digest());
        assert!(complete_node_quota_digest_v2(&foreign).is_err());
        let mut invalid = quotas[0];
        invalid.low_water_bytes = invalid.maximum_physical_bytes + 1;
        assert!(complete_node_quota_digest_v2(&[invalid]).is_err());
    }
}
