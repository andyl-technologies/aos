//! Quotes only the new selected Oracle banks and independent witness-plan clone.
//!
//! Programmes, schedule, paths, source roster, coordinator, shared reader/group,
//! Source/currentness callbacks and their serialization/error work are funded by
//! the caller before entry. This data does not grant any constructor permission.

use super::*;
use crate::node_qualification::packet_collection::complete::retained::{
    Counter, shared_requested_storage,
};
use crucible_engine::node_contract::RuntimeError;
use std::mem::{align_of, size_of};

/// Separates new retained requests, additional transient backing and fixed views.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PacketCompleteConstructionStorageData {
    /// Counts only new selected Rust allocation requests, not existing aliases.
    pub(crate) retained_requested_bytes: usize,
    /// Counts additional simultaneous heap requests within this closed component.
    pub(crate) maximum_simultaneous_transient_bytes: usize,
    /// Names fixed observation/construction views, excluding compiler recursion.
    pub(crate) declared_counter_scratch_bytes: usize,
}

impl PacketCompleteConstructionStorageData {
    /// Checks the complete selected layout row against the supplied ceiling.
    ///
    /// # Errors
    /// Refuses overflow or a retained/transient/scratch conjunction above maximum.
    pub(crate) fn new(
        retained: usize,
        transient: usize,
        scratch: usize,
        maximum: usize,
    ) -> Result<Self, RuntimeError> {
        let data = Self {
            retained_requested_bytes: retained,
            maximum_simultaneous_transient_bytes: transient,
            declared_counter_scratch_bytes: scratch,
        };
        if data.checked_peak_data()? > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(data)
    }

    /// Returns the checked conjunction without treating layout as mapped memory.
    ///
    /// # Errors
    /// Refuses arithmetic overflow; the caller separately admits the whole phase.
    pub(crate) fn checked_peak_data(&self) -> Result<usize, RuntimeError> {
        self.retained_requested_bytes
            .checked_add(self.maximum_simultaneous_transient_bytes)
            .and_then(|n| n.checked_add(self.declared_counter_scratch_bytes))
            .ok_or(RuntimeError::ResourceLimit)
    }
}

impl PacketCompleteNativeOracle {
    /// Quotes the real fixed banks and independent plan clone before allocation.
    ///
    /// All other moved inputs and callback/validation/serialization/error owners
    /// remain caller-funded. Empty banks reserve their actual private slot types;
    /// they do not charge fabricated future journal or operation DTOs.
    ///
    /// # Errors
    /// Refuses unsupported case counts, unknown plan backing or checked excess.
    pub(crate) fn original_shared_construction_storage_data(
        plan: &WitnessPlan,
        cases: usize,
        maximum: usize,
    ) -> Result<PacketCompleteConstructionStorageData, RuntimeError> {
        let mut counter = Counter::new(maximum);
        counter
            .add(
                shared_requested_storage(size_of::<Self>(), align_of::<Self>())
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .add(
                MAXIMUM_SEALS
                    .checked_mul(size_of::<Seal>())
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .add(
                3usize
                    .checked_mul(MAXIMUM_EFFECTS)
                    .and_then(|n| n.checked_mul(size_of::<effects::Effect>()))
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .add(original::OriginalBindings::reservation_requested_storage_data(cases, maximum)?)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        // Derived Clone requests the same occupied DTO fields. Existing String
        // and Vec capacities conservatively dominate their independently cloned
        // backing; actual BTree geometry comes from the pinned private walker.
        counter
            .charge(plan)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        PacketCompleteConstructionStorageData::new(
            counter.bytes(),
            0,
            Self::original_shared_construction_counter_scratch_data()?,
            maximum,
        )
    }

    /// Quotes the actual fixed counter and original construction views first.
    ///
    /// # Errors
    /// Refuses layout arithmetic overflow. Callback/serializer/compiler frames
    /// and kernel resources remain outside this selected component's window.
    pub(crate) fn original_shared_construction_counter_scratch_data() -> Result<usize, RuntimeError>
    {
        [
            size_of::<Counter>(),
            size_of::<PacketCompleteConstructionStorageData>(),
            size_of::<PacketCompleteSharedOracleRequest<'_>>(),
            size_of::<OracleInstallationRequest<'_>>(),
            size_of::<Self>(),
            size_of::<Observed>(),
            size_of::<std::cell::Ref<'_, Observed>>(),
            size_of::<Vec<Seal>>(),
            size_of::<[Vec<effects::Effect>; 3]>(),
            size_of::<original::OriginalBindings>(),
            original::OriginalBindings::reservation_scratch_data(),
            size_of::<WitnessPlan>(),
            8 * size_of::<usize>(),
        ]
        .into_iter()
        .try_fold(0usize, |n, v| {
            n.checked_add(v).ok_or(RuntimeError::ResourceLimit)
        })
    }

    /// Charges only the actual new banks/plan while the Oracle is still unused.
    ///
    /// The enclosing owner separately charges this Rc payload and the existing
    /// reader/group/roster/programme/schedule/path roots. Entered journal or
    /// original operation slots refuse instead of being priced as empty.
    ///
    /// # Errors
    /// Refuses a busy/entered bank, checked excess or unsupported plan backing.
    pub(crate) fn dormant_construction_backing_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        // This closed raw getter authenticates actual group creator before the
        // first observation loan; it performs no descriptor or kernel operation.
        let Self {
            roster: _,
            programmes: _,
            receiver_group,
            receiver_reader: _,
            effect_paths: _,
            schedule: _,
            plan,
            maximum_bytes: _,
            observed,
            originals,
        } = self;
        receiver_group.retained_descriptor_views_precredit_data()?;
        let observed = observed.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        let Observed {
            seals,
            effects,
            bytes,
            failed,
        } = &*observed;
        if !seals.is_empty()
            || effects.iter().any(|bank| !bank.is_empty())
            || *bytes != 0
            || *failed
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut counter = Counter::new(maximum);
        counter
            .add(
                seals
                    .capacity()
                    .checked_mul(size_of::<Seal>())
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        for bank in effects {
            counter
                .add(
                    bank.capacity()
                        .checked_mul(size_of::<effects::Effect>())
                        .ok_or(RuntimeError::ResourceLimit)?,
                )
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        counter
            .add(originals.empty_reservation_data()?)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .charge(plan)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        Ok(counter.bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_qualification::QualificationUnit;
    use std::collections::{BTreeMap, BTreeSet};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn same_shared_reader_owner_keeps_original_three_descriptors() -> TestResult {
        use std::os::unix::net::UnixDatagram;
        let pairs = [
            UnixDatagram::pair()?,
            UnixDatagram::pair()?,
            UnixDatagram::pair()?,
        ];
        let [(a, peer_a), (b, peer_b), (c, peer_c)] = pairs;
        let (group, reader) =
            crucible_engine::node_adapters::cnp::PacketCompleteEffectReceiverGroup::from_original_receivers(
                [a, b, c]
            );

        let original = Rc::new(reader);
        let selected = ReaderOwner::Shared(Rc::clone(&original)).into_shared();

        assert!(Rc::ptr_eq(&original, &selected));
        selected
            .authenticate_original_group(&group)
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(group.retained_descriptor_views_precredit_data()?, 3);
        assert_eq!(Rc::strong_count(&original), 2);
        drop((peer_a, peer_b, peer_c));
        Ok(())
    }

    #[test]
    fn real_private_banks_and_independent_plan_clone_fit_exact_and_refuse_one_short() -> TestResult
    {
        let reference =
            canonical::content_ref(b"original-layout-control", "application/octet-stream")?;
        let mut plan = WitnessPlan {
            schema: "crucible.node-witness-plan.v1".into(),
            unit: QualificationUnit {
                implementation: reference.clone(),
                realization: reference.clone(),
                descriptors: reference.clone(),
                contracts: reference.clone(),
                port_profiles: reference.clone(),
                environment: reference.clone(),
                harness: reference.clone(),
                fixtures: reference.clone(),
                specification: reference.clone(),
            },
            classes: BTreeSet::new(),
            requirements: BTreeMap::new(),
            cases: Vec::new(),
            limitations: reference,
        };
        plan.schema.reserve(37);
        let quote = PacketCompleteNativeOracle::original_shared_construction_storage_data(
            &plan,
            13,
            usize::MAX,
        )?;
        let mut seals = Vec::<Seal>::new();
        seals.try_reserve_exact(MAXIMUM_SEALS)?;
        let mut effects = [Vec::<effects::Effect>::new(), Vec::new(), Vec::new()];
        for bank in &mut effects {
            bank.try_reserve_exact(MAXIMUM_EFFECTS)?;
        }
        let originals = original::OriginalBindings::reserve(13)?;
        let cloned = plan.clone();
        let mut actual = Counter::new(usize::MAX);
        actual.add(shared_requested_storage(
            size_of::<PacketCompleteNativeOracle>(),
            align_of::<PacketCompleteNativeOracle>(),
        )?)?;
        actual.add(seals.capacity() * size_of::<Seal>())?;
        for bank in &effects {
            actual.add(bank.capacity() * size_of::<effects::Effect>())?;
        }
        actual.add(originals.empty_reservation_data()?)?;
        actual.charge(&cloned)?;
        assert!(quote.retained_requested_bytes >= actual.bytes());
        assert_ne!(plan.schema.as_ptr(), cloned.schema.as_ptr());
        let peak = quote.checked_peak_data()?;
        assert_eq!(
            PacketCompleteNativeOracle::original_shared_construction_storage_data(&plan, 13, peak)?,
            quote
        );
        assert!(
            PacketCompleteNativeOracle::original_shared_construction_storage_data(
                &plan,
                13,
                peak - 1
            )
            .is_err()
        );
        assert!(
            PacketCompleteNativeOracle::original_shared_construction_storage_data(
                &plan,
                0,
                usize::MAX
            )
            .is_err()
        );
        assert!(
            PacketCompleteNativeOracle::original_shared_construction_storage_data(
                &plan,
                129,
                usize::MAX
            )
            .is_err()
        );
        Ok(())
    }
}

impl PacketCompleteNativeOracle {
    pub(in crate::node_qualification::packet_collection::complete) fn charge_dormant_original_construction_data(
        &self,
        counter: &mut Counter,
    ) -> Result<(), RuntimeError> {
        counter
            .charge(&self.programmes)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .charge(&self.effect_paths)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .charge(&self.schedule)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .rc(&self.receiver_reader)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter
            .add(self.dormant_construction_backing_storage_data(counter.remaining())?)
            .map_err(|_| RuntimeError::ResourceLimit)
    }
}
