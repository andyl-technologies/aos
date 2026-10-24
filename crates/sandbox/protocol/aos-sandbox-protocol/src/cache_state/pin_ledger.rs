//! Sole passive Cache pin-ledger replay, uniqueness and usage engine.
//!
//! Standard Borrow projections read historical fields from the actual rows.
//! The Native instantiation retains its private verifier wrappers in these
//! SAME maps; the historical instantiation uses concrete DATA rows. This owner
//! neither constructs a Native wrapper nor grants current pin/drain authority.

use std::{borrow::Borrow, collections::BTreeMap};
use aos_sandbox_model::{AttachmentId, ObjectDescriptor, ObjectDigest, ProjectId, ViewId};
use super::{AccountingError, CacheUsageV1, PhysicalPartitionId, object_descriptor_commitment};
use super::pin_data::{CachePinId, CachePinKindV1, CachePinDataV1, PinDrainEvidenceDataV1,
    PinDataErrorV1, validate_release};
use super::pin_floor::PinCompactionFloorDataV1;

/// Retains a historical pin row and its exact historical drain row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasedCachePinDataV1<P = CachePinDataV1, D = PinDrainEvidenceDataV1> {
    /// Complete retained pin row, including an optional Native private wrapper.
    pub pin: P,
    /// Complete retained drain row, including an optional Native private wrapper.
    pub drain: D,
}

/// Names one exact logical consumer within a physical partition.
pub type LogicalPinConsumerKeyV1 = (
    ObjectDigest, ObjectDigest, ProjectId, ViewId, Option<AttachmentId>,
);

/// Owns the bounded historical pin namespace and exact retained row carriers.
#[derive(Clone, Debug)]
pub struct CachePinLedgerDataV1<P = CachePinDataV1, D = PinDrainEvidenceDataV1, F = PinCompactionFloorDataV1> {
    /// Maximum combined retained active and released rows.
    pub maximum_records: usize,
    /// Exact active rows, including actual opaque wrappers when supplied.
    pub pins: BTreeMap<CachePinId, P>,
    /// Unique logical consumer namespace.
    pub logical_consumers: BTreeMap<LogicalPinConsumerKeyV1, CachePinId>,
    /// Exact released rows above the historical floor.
    pub released: BTreeMap<CachePinId, ReleasedCachePinDataV1<P, D>>,
    /// Historical non-reuse floor.
    pub compacted_through: Option<F>,
}

impl<P, D, F> CachePinLedgerDataV1<P, D, F>
where
    P: Borrow<CachePinDataV1>,
    D: Borrow<PinDrainEvidenceDataV1> + Copy,
    F: Borrow<PinCompactionFloorDataV1> + Copy,
{
    /// Constructs an empty bounded historical pin ledger.
    ///
    /// # Errors
    ///
    /// Returns the corresponding historical capacity, shape, identity or usage error.
    pub fn new(maximum_records: usize) -> Result<Self, PinDataErrorV1> {
        if maximum_records == 0 || maximum_records > 1_000_000 {
            return Err(PinDataErrorV1::Capacity);
        }
        Ok(Self {
            maximum_records,
            pins: BTreeMap::new(),
            logical_consumers: BTreeMap::new(),
            released: BTreeMap::new(),
            compacted_through: None,
        })
    }

    /// Replays exact retained rows with bounded uniqueness checks.
    ///
    /// # Errors
    ///
    /// Returns the corresponding historical capacity, shape, identity or usage error.
    pub fn replay(
        maximum_records: usize,
        compacted_through: Option<F>,
        pins: impl IntoIterator<Item = P>,
        released: impl IntoIterator<Item = ReleasedCachePinDataV1<P, D>>,
    ) -> Result<Self, PinDataErrorV1> {
        let mut ledger = Self::new(maximum_records)?;
        ledger.compacted_through = compacted_through;
        for pin in pins {
            let pin_data: &CachePinDataV1 = pin.borrow();
            pin_data.validate_ref()?;
            if ledger
                .compacted_through
                .is_some_and(|floor| {
                    let floor: &PinCompactionFloorDataV1 = floor.borrow();
                    pin_data.id <= floor.pin
                })
            {
                return Err(PinDataErrorV1::Conflict);
            }
            if ledger.pins.len() + ledger.released.len() >= ledger.maximum_records {
                return Err(PinDataErrorV1::Capacity);
            }
            if let Some(key) = logical_consumer_key(pin_data)
                && ledger.logical_consumers.insert(key, pin_data.id).is_some()
            {
                return Err(PinDataErrorV1::Conflict);
            }
            if ledger.pins.insert(pin_data.id, pin).is_some() {
                return Err(PinDataErrorV1::Conflict);
            }
        }
        for tombstone in released {
            let pin_data: &CachePinDataV1 = tombstone.pin.borrow();
            validate_release(pin_data, *tombstone.drain.borrow())?;
            if ledger
                .compacted_through
                .is_some_and(|floor| {
                    let floor: &PinCompactionFloorDataV1 = floor.borrow();
                    pin_data.id <= floor.pin
                })
            {
                return Err(PinDataErrorV1::Conflict);
            }
            if ledger.pins.len() + ledger.released.len() >= ledger.maximum_records {
                return Err(PinDataErrorV1::Capacity);
            }
            if ledger.pins.contains_key(&pin_data.id)
                || ledger.released.contains_key(&pin_data.id)
            {
                return Err(PinDataErrorV1::Conflict);
            }
            ledger.released.insert(pin_data.id, tombstone);
        }
        Ok(ledger)
    }

    /// Reports historical non-source-retention reclamation blockers.
    pub fn blocks_eviction(
        &self,
        partition: PhysicalPartitionId,
        object: &ObjectDescriptor,
    ) -> bool {
        self.pins.values().any(|pin| {
            let pin: &CachePinDataV1 = pin.borrow();
            pin.partition == partition
                && &pin.object == object
                && pin.kind != CachePinKindV1::SourceRetention
        })
    }

    /// Borrows the exact supplied retained row without issuing authority.
    pub fn pin(&self, id: CachePinId) -> Option<&P> {
        self.pins.get(&id)
    }

    /// Finds the sole retained logical row for an exact consumer.
    pub fn logical_consumer_pin(
        &self,
        partition: PhysicalPartitionId,
        object: &ObjectDescriptor,
        project: ProjectId,
        view: ViewId,
        attachment: Option<AttachmentId>,
    ) -> Option<&P> {
        let key = (
            partition.digest(),
            object_descriptor_commitment(object),
            project,
            view,
            attachment,
        );
        self.logical_consumers
            .get(&key)
            .and_then(|id| self.pins.get(id))
            .filter(|pin| {
                let pin: &CachePinDataV1 = (*pin).borrow();
                pin.partition == partition
                    && &pin.object == object
                    && pin.project == project
                    && pin.view == view
                    && pin.attachment == attachment
                    && pin.kind == CachePinKindV1::LogicalLease
            })
    }

    /// Selects the next historical identity above all retained and compacted rows.
    ///
    /// # Errors
    ///
    /// Returns the corresponding historical capacity, shape, identity or usage error.
    pub fn next_pin_id(&self) -> Result<CachePinId, PinDataErrorV1> {
        let greatest = [
            self.pins.last_key_value().map(|(id, _)| *id),
            self.released.last_key_value().map(|(id, _)| *id),
            self.compacted_through.map(|floor| {
                let floor: &PinCompactionFloorDataV1 = floor.borrow();
                floor.pin
            }),
        ]
        .into_iter()
        .flatten()
        .max();
        let next = greatest.map_or(Some(1), |id| {
            u128::from_be_bytes(*id.as_bytes()).checked_add(1)
        });
        CachePinId::from_bytes(next.ok_or(PinDataErrorV1::Capacity)?.to_be_bytes())
    }

    /// Iterates the actual supplied retained row carriers.
    pub fn values(&self) -> impl Iterator<Item = &P> {
        self.pins.values()
    }

    /// Counts complete historical pin-class usage for quota validation.
    ///
    /// # Errors
    ///
    /// Returns the corresponding historical capacity, shape, identity or usage error.
    pub fn usage(
        &self,
    ) -> Result<(BTreeMap<[u8; 16], CacheUsageV1>, CacheUsageV1), AccountingError> {
        let mut projects = BTreeMap::<[u8; 16], CacheUsageV1>::new();
        let mut node = CacheUsageV1::default();
        for pin in self.pins.values() {
            let pin: &CachePinDataV1 = pin.borrow();
            let project = projects.entry(*pin.project.as_bytes()).or_default();
            match pin.kind {
                CachePinKindV1::LogicalLease => {
                    increment(&mut project.logical_pins)?;
                    increment(&mut node.logical_pins)?;
                }
                CachePinKindV1::SourceRetention => {
                    increment(&mut project.source_retentions)?;
                    increment(&mut node.source_retentions)?;
                }
                CachePinKindV1::KernelReference => {
                    increment(&mut project.kernel_references)?;
                    increment(&mut node.kernel_references)?;
                }
                CachePinKindV1::BackingRegistration => {
                    increment(&mut project.backing_registrations)?;
                    increment(&mut node.backing_registrations)?;
                }
            }
        }
        Ok((projects, node))
    }

}

/// Projects the exact historical logical consumer key.
#[doc(hidden)]
pub fn logical_consumer_key(pin: &CachePinDataV1) -> Option<LogicalPinConsumerKeyV1> {
    (pin.kind == CachePinKindV1::LogicalLease).then(|| {
        (
            pin.partition.digest(),
            object_descriptor_commitment(&pin.object),
            pin.project,
            pin.view,
            pin.attachment,
        )
    })
}

fn increment(value: &mut u64) -> Result<(), AccountingError> {
    *value = value.checked_add(1).ok_or(AccountingError::Overflow)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::{CacheDomainId, MediaType, model::{CacheDomain, CacheDomainKind}};
    use crate::cache_state::{CacheNodeIdV1, ProtectedBackingIdentityV1};

    fn pin(identity: u8) -> CachePinDataV1 {
        let partition = PhysicalPartitionId::derive(
            CacheNodeIdV1::from_bytes([1; 16]).unwrap(),
            ProtectedBackingIdentityV1::new(
                ObjectDigest::from_bytes([2; 32]), ObjectDigest::from_bytes([3; 32]),
                ObjectDigest::from_bytes([4; 32]), ObjectDigest::from_bytes([5; 32]),
            ).unwrap(),
            CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([6; 16])),
            ObjectDigest::from_bytes([7; 32]),
        ).unwrap();
        CachePinDataV1::recover_historical(
            CachePinId::from_bytes([identity; 16]).unwrap(),
            partition,
            ObjectDescriptor::new(MediaType::new("application/octet-stream").unwrap(), ObjectDigest::from_bytes([8; 32]), 1),
            ProjectId::from_bytes([9; 16]), ViewId::from_bytes([10; 16]),
            None, None, None, CachePinKindV1::LogicalLease, 0, 100,
            ObjectDigest::from_bytes([11; 32]),
        ).unwrap()
    }

    struct OwnedRow {
        data: CachePinDataV1,
        anchor: Box<u8>,
    }

    impl Borrow<CachePinDataV1> for OwnedRow {
        fn borrow(&self) -> &CachePinDataV1 {
            &self.data
        }
    }

    #[test]
    fn replay_keeps_the_exact_nonclone_row_and_counts_its_usage() {
        let data = pin(1);
        let identity = data.id;
        let row = OwnedRow { data, anchor: Box::new(7) };
        let anchor = std::ptr::from_ref(row.anchor.as_ref());
        let ledger = CachePinLedgerDataV1::<OwnedRow>::replay(2, None, [row], []).unwrap();

        assert_eq!(std::ptr::from_ref(ledger.pin(identity).unwrap().anchor.as_ref()), anchor);
        let (projects, node) = ledger.usage().unwrap();
        assert_eq!(node.logical_pins, 1);
        assert_eq!(projects[&[9; 16]].logical_pins, 1);
        assert_eq!(ledger.next_pin_id().unwrap().as_bytes(), &u128::from_be_bytes([1; 16]).checked_add(1).unwrap().to_be_bytes());
    }

    #[test]
    fn replay_preserves_capacity_consumer_and_tombstone_conflict_frontiers() {
        let first = pin(1);
        let second = pin(2);
        assert!(matches!(CachePinLedgerDataV1::<CachePinDataV1>::replay(1, None, [first.clone(), second.clone()], []), Err(PinDataErrorV1::Capacity)));
        assert!(matches!(CachePinLedgerDataV1::<CachePinDataV1>::replay(2, None, [first.clone(), second], []), Err(PinDataErrorV1::Conflict)));

        let drain = PinDrainEvidenceDataV1::recover_historical(
            &first, crate::cache_state::pin_data::PinDrainOutcomeV1::NeverInstalled,
            ObjectDigest::from_bytes([12; 32]), 100,
        ).unwrap();
        let tombstone = ReleasedCachePinDataV1 { pin: first.clone(), drain };
        assert!(matches!(CachePinLedgerDataV1::<CachePinDataV1>::replay(2, None, [first], [tombstone]), Err(PinDataErrorV1::Conflict)));
    }
}
