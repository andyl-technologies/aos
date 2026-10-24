//! Observes original Clock collection owners without virtual source callbacks.
//!
//! The caller charges the same concrete Source root separately. Unknown protocol
//! and quantized observations refuse; their empty tree layouts still count.
//! Serialized collection credit is never substituted for requested backing.

use super::*;
use crate::node_qualification::{
    RetainedMetadataCounter as Counter, RetainedMetadataOwned as Owned,
};
use crucible_engine::node_state::borrowed_btree_map_requested_storage_precredit_data;

fn unknown() -> QualificationError {
    QualificationError::Refused("unsupported original Clock collection owner")
}

fn unused_observation_map<K, V>(
    map: &BTreeMap<K, V>,
    counter: &mut Counter,
) -> Result<(), QualificationError> {
    if !map.is_empty() {
        return Err(unknown());
    }
    let bytes = borrowed_btree_map_requested_storage_precredit_data(map, counter.remaining())
        .map_err(|_| unknown())?;
    counter.add(bytes)
}

impl ProductionConformanceRunner<'_> {
    pub(crate) fn charge_original_clock_storage_data(
        &self,
        original_source: &dyn InstalledConformanceAuthority,
        counter: &mut Counter,
    ) -> Result<(), QualificationError> {
        let Self {
            process,
            owner_thread,
            authority,
            node,
            binding,
            plan,
            population_reference,
            population,
            attempts,
            reservation_owner,
            observations,
            source_inspections,
            clock_state_observations,
            clock_adverse_observations,
            exact_observations,
            quantized_observations,
            limits: _,
            reserved_bytes: _,
        } = self;
        if *process != std::process::id()
            || *owner_thread != std::thread::current().id()
            || !std::ptr::addr_eq(*authority, original_source)
        {
            return Err(unknown());
        }
        counter.charge(node)?;
        counter.charge(binding)?;
        counter.charge(plan)?;
        counter.charge(population_reference)?;
        counter.charge(population)?;
        counter.charge(attempts)?;
        counter.rc(reservation_owner)?;
        unused_observation_map(observations, counter)?;
        counter.charge(source_inspections)?;
        counter.charge(clock_state_observations)?;
        counter.charge(clock_adverse_observations)?;
        counter.charge(exact_observations)?;
        unused_observation_map(quantized_observations, counter)
    }
}

impl Owned for ExactCompletionObservation {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let Self {
            schema: _,
            case,
            snapshot,
            snapshot_ref,
            objects,
        } = self;
        counter.charge(case)?;
        counter.charge(snapshot)?;
        counter.charge(snapshot_ref)?;
        counter.charge(objects)
    }
}

impl Owned for CollectedConformance {
    fn charge(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        let Self {
            attempts,
            issued,
            observations,
            source_inspections,
            clock_state_observations,
            clock_adverse_observations,
            exact_observations,
            quantized_observations,
        } = self;
        counter.charge(attempts)?;
        match issued {
            Ok(issued) => counter.charge(issued)?,
            Err(error) => counter.charge(error)?,
        }
        unused_observation_map(observations, counter)?;
        counter.charge(source_inspections)?;
        counter.charge(clock_state_observations)?;
        counter.charge(clock_adverse_observations)?;
        counter.charge(exact_observations)?;
        unused_observation_map(quantized_observations, counter)
    }
}
