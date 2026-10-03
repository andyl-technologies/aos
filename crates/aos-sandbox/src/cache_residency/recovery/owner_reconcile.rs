//! Read-only comparison of protected logical pins with the physical owner.

use crate::cache_residency::{
    CacheOwnerErrorV1, CacheOwnerPinIdV1, CacheOwnerPinPresenceV1, CacheOwnerPinSnapshotV1,
    CachePinCompactionPhysicalProofV1, CachePinId, CachePinKindV1, CachePinV1,
};

use super::CacheRecoveryInventoryV1;

/// Reports one exact logical pin whose protected and physical states disagree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheLogicalOwnerPinDiscrepancyV1 {
    /// Exact protected pin or release tombstone that must be reconciled.
    pub pin: CachePinV1,
    /// Presence required by the latest protected cache projection.
    pub expected: CacheOwnerPinPresenceV1,
    /// Presence observed in the validated physical-owner manifest.
    pub observed: CacheOwnerPinPresenceV1,
}

impl CacheRecoveryInventoryV1 {
    /// Proves that every retained release through a proposed floor is absent.
    ///
    /// The resulting proof borrows this validated owner snapshot and can only
    /// compact the exact released-ID prefix that the ledger still retains.
    ///
    /// # Errors
    ///
    /// Returns an error for mismatched partitions, conflicting owner pins, or
    /// duplicate retained identities.
    pub fn prove_released_pin_compaction_absence<'snapshot, 'owner>(
        &self,
        owner: &'snapshot CacheOwnerPinSnapshotV1<'owner>,
        floor: CachePinId,
    ) -> Result<CachePinCompactionPhysicalProofV1<'snapshot>, CacheOwnerErrorV1> {
        if self.authority_poisoned {
            return Err(CacheOwnerErrorV1::RecoveryMismatch);
        }
        let partition = self.global.node_quota.partition;
        let mut released = Vec::new();
        for payload in &self.reconstructed {
            if payload.plan.partition != partition {
                return Err(CacheOwnerErrorV1::RecoveryMismatch);
            }
            for tombstone in &payload.released_pins {
                let pin = &tombstone.pin;
                if pin.partition != partition {
                    return Err(CacheOwnerErrorV1::RecoveryMismatch);
                }
                if pin.id > floor {
                    continue;
                }

                let id = CacheOwnerPinIdV1::for_cache_pin(partition, pin.id)?;
                if owner.observe_pin(id, partition, &pin.object)? != CacheOwnerPinPresenceV1::Absent
                {
                    return Err(CacheOwnerErrorV1::RecoveryMismatch);
                }
                released.push(pin.id);
            }
        }
        released.sort_unstable();
        if released.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CacheOwnerErrorV1::RecoveryMismatch);
        }
        Ok(CachePinCompactionPhysicalProofV1::from_verified(
            partition, floor, released,
        ))
    }

    /// Compares every logical pin and release tombstone with one owner snapshot.
    ///
    /// The inventory is retained state, not permission to acquire or release a
    /// physical pin. A controller must revalidate protected postcommit authority
    /// before performing any effect suggested by these discrepancies.
    ///
    /// # Errors
    ///
    /// Returns an error when a pin escapes this partition or the owner manifest
    /// contains a conflicting identity or inconsistent index.
    pub fn observe_logical_owner_pins(
        &self,
        owner: &CacheOwnerPinSnapshotV1<'_>,
    ) -> Result<Vec<CacheLogicalOwnerPinDiscrepancyV1>, CacheOwnerErrorV1> {
        let partition = self.global.node_quota.partition;
        let mut discrepancies = Vec::new();
        for payload in &self.reconstructed {
            if payload.plan.partition != partition {
                return Err(CacheOwnerErrorV1::RecoveryMismatch);
            }
            for pin in &payload.pins {
                if pin.kind == CachePinKindV1::LogicalLease {
                    observe_logical_pin(
                        owner,
                        partition,
                        pin,
                        CacheOwnerPinPresenceV1::Present,
                        &mut discrepancies,
                    )?;
                }
            }
            for released in &payload.released_pins {
                if released.pin.kind == CachePinKindV1::LogicalLease {
                    observe_logical_pin(
                        owner,
                        partition,
                        &released.pin,
                        CacheOwnerPinPresenceV1::Absent,
                        &mut discrepancies,
                    )?;
                }
            }
        }
        Ok(discrepancies)
    }
}

fn observe_logical_pin(
    owner: &CacheOwnerPinSnapshotV1<'_>,
    partition: crate::cache_residency::PhysicalPartitionId,
    pin: &CachePinV1,
    expected: CacheOwnerPinPresenceV1,
    discrepancies: &mut Vec<CacheLogicalOwnerPinDiscrepancyV1>,
) -> Result<(), CacheOwnerErrorV1> {
    if pin.partition != partition {
        return Err(CacheOwnerErrorV1::RecoveryMismatch);
    }
    let id = CacheOwnerPinIdV1::for_cache_pin(partition, pin.id)?;
    let observed = owner.observe_pin(id, pin.partition, &pin.object)?;
    if observed != expected {
        discrepancies.push(CacheLogicalOwnerPinDiscrepancyV1 {
            pin: pin.clone(),
            expected,
            observed,
        });
    }
    Ok(())
}
