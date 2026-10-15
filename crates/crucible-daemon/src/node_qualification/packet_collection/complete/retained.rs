//! Counts actual daemon-owned metadata without following borrowed source owners.
//!
//! Inline slots are charged by their containing Vec, Box, Rc or tree node.
//! Equal fullrefs do not deduplicate independent allocations. Only stable actual
//! Rc/Arc data addresses can share a retained owner in this bounded walk.

use std::{
    collections::{BTreeMap, BTreeSet},
    mem::{align_of, size_of},
    path::PathBuf,
    rc::{Rc, Weak},
};

use crucible::node_state::{
    borrowed_btree_map_requested_storage, borrowed_btree_set_requested_storage,
};
use crucible_node_contract::{
    Bytes, ConnectionDescriptor, ContentRef, Endpoint, HashRef, Id, NodeBindingRef, SchemaRef,
    WorldBinding,
};

use crate::node_qualification::{
    AcceptanceDecision, AcceptanceRecord, CaseEvidence, PlannedWitnessCase, QualificationClaim,
    QualificationClass, QualificationError, QualificationUnit, RequirementResult, WitnessCriterion,
    WitnessPlan,
};

use crucible::node_adapters::cnp::PacketCompleteSemanticSource;
use crucible_node_provider::retained_metadata::RetainedProtocolMetadataFacts;

const SHARED_OWNERS: usize = 128;

pub(in crate::node_qualification::packet_collection) struct Counter {
    bytes: usize,
    maximum: usize,
    shared: [Option<*const ()>; SHARED_OWNERS],
    shared_used: usize,
}

impl Counter {
    pub(in crate::node_qualification::packet_collection) fn new(maximum: usize) -> Self {
        Self {
            bytes: 0,
            maximum,
            shared: [None; SHARED_OWNERS],
            shared_used: 0,
        }
    }

    pub(in crate::node_qualification::packet_collection) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(in crate::node_qualification::packet_collection) fn remaining(&self) -> usize {
        self.maximum - self.bytes
    }

    pub(in crate::node_qualification::packet_collection) fn add(
        &mut self,
        bytes: usize,
    ) -> Result<(), QualificationError> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.maximum)
            .ok_or_else(exhausted)?;
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection) fn charge(
        &mut self,
        value: &impl Owned,
    ) -> Result<(), QualificationError> {
        value.charge(self)
    }

    pub(in crate::node_qualification::packet_collection) fn metadata(
        &mut self,
        facts: &RetainedProtocolMetadataFacts,
    ) -> Result<(), QualificationError> {
        let bytes = PacketCompleteSemanticSource::complete_retained_metadata_storage_data(
            facts,
            self.remaining(),
        )
        .map_err(|_| exhausted())?;
        self.add(bytes)
    }

    /// Admits an actual shared allocation once; callers then walk its fields.
    pub(in crate::node_qualification::packet_collection) fn rc<T>(
        &mut self,
        owner: &Rc<T>,
    ) -> Result<bool, QualificationError> {
        self.shared_header(Rc::as_ptr(owner).cast(), size_of::<T>(), align_of::<T>())
    }

    /// Charges a retained Weak without marking any strong payload as walked.
    pub(in crate::node_qualification::packet_collection) fn weak<T>(
        &mut self,
        _owner: &Weak<T>,
    ) -> Result<(), QualificationError> {
        self.add(shared_requested_storage(size_of::<T>(), align_of::<T>())?)
    }

    pub(in crate::node_qualification::packet_collection) fn shared_header(
        &mut self,
        identity: *const (),
        inline: usize,
        alignment: usize,
    ) -> Result<bool, QualificationError> {
        if self.shared[..self.shared_used].contains(&Some(identity)) {
            return Ok(false);
        }
        if self.shared_used == self.shared.len() {
            return Err(exhausted());
        }
        let bytes = shared_requested_storage(inline, alignment)?;
        self.add(bytes)?;
        self.shared[self.shared_used] = Some(identity);
        self.shared_used += 1;
        Ok(true)
    }
}

// Uses the same checked requested layout for strong and conservative Weak views.
fn shared_requested_storage(inline: usize, alignment: usize) -> Result<usize, QualificationError> {
    let padding = alignment
        .max(align_of::<usize>())
        .checked_sub(1)
        .and_then(|value| value.checked_mul(2))
        .ok_or_else(exhausted)?;
    inline
        .checked_add(2 * size_of::<usize>())
        .and_then(|bytes| bytes.checked_add(padding))
        .ok_or_else(exhausted)
}

pub(in crate::node_qualification::packet_collection) trait Owned {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError>;
}

impl Owned for String {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        counter.add(self.capacity())
    }
}

impl Owned for Id {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        counter.add(self.allocated_capacity())
    }
}

impl Owned for PathBuf {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        counter.add(self.capacity())
    }
}

impl Owned for Bytes {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        counter.add(self.allocation_capacity())
    }
}

impl Owned for u8 {
    fn charge(&self, _: &mut Counter) -> Result<(), QualificationError> {
        Ok(())
    }
}

macro_rules! scalar {
    ($($kind:ty),+ $(,)?) => { $(impl Owned for $kind {
        fn charge(&self, _: &mut Counter) -> Result<(), QualificationError> { Ok(()) }
    })+ };
}

scalar!(
    u16,
    crucible_node_contract::U64,
    crucible_node_contract::Position,
    crate::node_qualification::CaseKind,
    crate::node_qualification::CaseVerdict,
    crate::node_qualification::RequirementDisposition,
    super::super::connected::PacketConnectedCaseKind
);

impl Owned for QualificationClass {
    fn charge(&self, _: &mut Counter) -> Result<(), QualificationError> {
        Ok(())
    }
}

impl<T: Owned> Owned for Vec<T> {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        counter.add(
            self.capacity()
                .checked_mul(size_of::<T>())
                .ok_or_else(exhausted)?,
        )?;
        for value in self {
            value.charge(counter)?;
        }
        Ok(())
    }
}

impl<T: Owned> Owned for Option<T> {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        if let Some(value) = self {
            value.charge(counter)?;
        }
        Ok(())
    }
}

impl<A: Owned, B: Owned> Owned for (A, B) {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        self.0.charge(counter)?;
        self.1.charge(counter)
    }
}

impl<K: Owned, V: Owned> Owned for BTreeMap<K, V> {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        counter.add(
            borrowed_btree_map_requested_storage(self, counter.remaining())
                .map_err(|_| exhausted())?,
        )?;
        for (key, value) in self {
            key.charge(counter)?;
            value.charge(counter)?;
        }
        Ok(())
    }
}

impl<T: Owned> Owned for BTreeSet<T> {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        counter.add(
            borrowed_btree_set_requested_storage(self, counter.remaining())
                .map_err(|_| exhausted())?,
        )?;
        for value in self {
            value.charge(counter)?;
        }
        Ok(())
    }
}

macro_rules! fields {
    ($kind:ty; $($field:ident),+ $(,)?) => {
        impl Owned for $kind {
            fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
                let Self { $($field),+ } = self;
                $($field.charge(counter)?;)+
                Ok(())
            }
        }
    };
}

impl<T: Owned, const N: usize> Owned for [T; N] {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        for value in self {
            value.charge(counter)?;
        }
        Ok(())
    }
}

fields!(super::super::PacketFixtureArtifact; role, path, content);
fields!(super::super::PacketFixtureMeasurements; peer, host, sources);
fields!(crucible::node_contract::OwnerIdentity; owner, incarnation, generation);
fields!(crucible::node_contract::NodeRoute; node, owners);
fields!(crucible::node_contract::ActivationRecord; generation, activation_id, world_binding_hash, owners, boundary);
fields!(super::super::connected::PacketConnectedGrant; node, operation, request);
fields!(super::super::connected::PacketConnectedCase; id, kind, node, operation);
fields!(super::super::connected::PacketConnectedSchedule; nodes, grants, cases);

impl Owned for crucible::node_contract::OperationRequest {
    fn charge(&self, _: &mut Counter) -> Result<(), QualificationError> {
        // This is the exact installed complete schedule, whose requests have
        // full scalar positions only. Other operation families stay closed.
        match self {
            Self::ExactRun {
                start: _,
                limit: _,
                boundary_policy: _,
            }
            | Self::BoundarySettle { start: _, limit: _ } => Ok(()),
            _ => Err(QualificationError::Refused(
                "unselected complete daemon request layout",
            )),
        }
    }
}

fields!(HashRef; algorithm, domain, digest);
fields!(ContentRef; hash, length, media_type);
fields!(Endpoint; node_id, port_id, lane_id);
fields!(SchemaRef; id, version, definition, extensions);
fields!(NodeBindingRef; node_id, binding_hash, extensions);
fields!(WorldBinding; schema_version, scenario_ref, node_bindings, connections, ownership_ref, coordinator_contract_ref, ordering_profile, initialization_ref, extensions);
fields!(ConnectionDescriptor; schema_version, id, producer, consumer, interface_id, features, payload_schema, minimum_latency_ps, policy_ref, capture_owner_id, extensions);
fields!(QualificationUnit; implementation, realization, descriptors, contracts, port_profiles, environment, harness, fixtures, specification);
fields!(PlannedWitnessCase; id, kind, classes, oracle);
fields!(WitnessPlan; schema, unit, classes, requirements, cases, limitations);
fields!(CaseEvidence; case, kind, verdict, classes, result, oracle);
fields!(RequirementResult; requirement, disposition, cases, not_applicable_reason);
fields!(QualificationClaim; format, version, unit, classes, catalog, applicability_policy, requirements, supersedes, limitations);
fields!(AcceptanceRecord; format, version, original_claim, original, evaluated_unit, required_classes, missing_requirements, decision);

impl Owned for WitnessCriterion {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        match self {
            Self::Applicable { cases, criterion } => {
                cases.charge(counter)?;
                criterion.charge(counter)
            }
            Self::NotApplicable { reason, criterion } => {
                reason.charge(counter)?;
                criterion.charge(counter)
            }
        }
    }
}

impl Owned for AcceptanceDecision {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        match self {
            Self::Accepted => Ok(()),
            Self::Refused { diagnostic } => diagnostic.charge(counter),
        }
    }
}

impl Owned for serde_json::Value {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        // The complete scene's closed identity contracts require empty extension
        // maps. Do not invent a generic dynamic-Value heap bound here; a future
        // explicitly selected nonempty extension needs its own actual observer.
        let _ = counter;
        Err(QualificationError::Refused(
            "complete daemon metadata contains an unselected dynamic Value",
        ))
    }
}

fn exhausted() -> QualificationError {
    QualificationError::Refused("complete daemon retained allocation exceeds admitted storage")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_equal_buffers_count_both_spare_capacities() -> Result<(), QualificationError> {
        let mut first = String::with_capacity(4096);
        first.push_str("same");
        let second = first.clone();
        let mut counter = Counter::new(8192);
        counter.charge(&first)?;
        counter.charge(&second)?;
        assert_eq!(counter.bytes(), first.capacity() + second.capacity());
        Ok(())
    }

    #[test]
    fn weak_view_preserves_later_strong_nested_walk() -> Result<(), QualificationError> {
        let strong = Rc::new(String::with_capacity(2048));
        let weak = Rc::downgrade(&strong);
        let mut counter = Counter::new(8192);

        counter.weak(&weak)?;
        let header = counter.bytes();
        assert!(counter.rc(&strong)?);
        counter.charge(strong.as_ref())?;
        assert_eq!(counter.bytes(), 2 * header + strong.capacity());
        assert!(!counter.rc(&strong)?);

        let mut exact = Counter::new(header);
        exact.weak(&weak)?;
        assert_eq!(exact.bytes(), header);
        assert!(Counter::new(header - 1).weak(&weak).is_err());
        Ok(())
    }

    #[test]
    fn actual_shared_allocation_is_counted_once_but_equal_new_owner_is_separate()
    -> Result<(), QualificationError> {
        let first = Rc::new(7u64);
        let alias = Rc::clone(&first);
        let independent = Rc::new(7u64);
        let mut counter = Counter::new(1024);
        assert!(counter.rc(&first)?);
        let one = counter.bytes();
        assert!(!counter.rc(&alias)?);
        assert_eq!(counter.bytes(), one);
        assert!(counter.rc(&independent)?);
        assert_eq!(counter.bytes(), 2 * one);
        Ok(())
    }
}
