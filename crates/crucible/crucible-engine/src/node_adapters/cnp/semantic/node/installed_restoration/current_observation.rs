//! Consumes a genuine current-inspection claim beside immutable imported custody.
//!
//! Separate slots retain every successful or failed recurring inspection. Both
//! scheduling copies are initialized under SourceRead before its final fence.
//! A new claim never overwrites the first observation or its once-only slots.

use super::*;
use crate::node_admission::{
    OriginalRestoredSchedulingObservationClaim,
    OriginalRestoredSchedulingObservationConstructionData,
};
use crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacitySink;
use crate::node_scheduling::NativeSchedulingObservation;
use crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch;

#[derive(serde::Serialize)]
pub(super) struct CurrentNodeObservation {
    ordinal: u64,
    retained: Option<NativeSchedulingObservation>,
    returned: Option<NativeSchedulingObservation>,
}

impl super::super::super::CnpSemanticNode {
    pub(in crate::node_adapters::cnp::semantic) fn seed_installed_restored_suffix_data(
        &self,
        world: &WorldActivation,
    ) -> Result<(), RuntimeError> {
        let native = self
            .preparation
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let source = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let controller = native
            .controller
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let selected = native
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.installed_restoration.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        selected.association.seed_original_restored_suffix_data(
            source.as_ref(),
            controller,
            Rc::as_ptr(&native.read_owner).cast(),
            world,
        )
    }

    pub(in crate::node_adapters::cnp::semantic) fn quote_installed_current_observation_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
        ordinal: u64,
        maximum: usize,
    ) -> Result<OriginalRestoredSchedulingObservationConstructionData, RuntimeError> {
        let native = self
            .preparation
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let source = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let controller = native
            .controller
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let selected = native
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.installed_restoration.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !selected.installed || !selected.observation_attempted {
            return Err(RuntimeError::OutstandingObligations);
        }
        selected
            .association
            .quote_original_current_observation_data(
                source.as_ref(),
                controller,
                Rc::as_ptr(&native.read_owner).cast(),
                launch,
                canonical_launch5,
                ordinal,
                maximum,
            )
    }

    pub(in crate::node_adapters::cnp::semantic) fn observe_installed_current_data(
        &mut self,
        claim: &OriginalRestoredSchedulingObservationClaim<'_>,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        self.current()?;
        self.try_observe_installed_current_data(claim)
            .map_err(current_failure)
    }

    fn try_observe_installed_current_data(
        &mut self,
        claim: &OriginalRestoredSchedulingObservationClaim<'_>,
    ) -> Result<NativeSchedulingObservation, RuntimeError> {
        let native = self
            .preparation
            .guard
            .custody
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let source = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let controller = native
            .controller
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let selected = native
            .runtime
            .as_mut()
            .and_then(|runtime| runtime.installed_restoration.as_mut())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !selected.installed {
            return Err(RuntimeError::OutstandingObligations);
        }
        let row = claim.row_data();
        if row.ordinal
            != u64::try_from(selected.current_observations.len())
                .map_err(|_| RuntimeError::ResourceLimit)?
                .checked_add(1)
                .ok_or(RuntimeError::ResourceLimit)?
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        selected
            .current_observations
            .try_reserve_exact(1)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        selected.current_observations.push(CurrentNodeObservation {
            ordinal: row.ordinal,
            retained: None,
            returned: None,
        });
        let attempt = selected
            .current_observations
            .last_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        selected
            .association
            .call_original_current_observation_into(
                source.as_ref(),
                controller,
                Rc::as_ptr(&native.read_owner).cast(),
                claim,
                &mut attempt.retained,
                &mut attempt.returned,
            )?;
        attempt.returned.take().ok_or(RuntimeError::InvalidReceipt)
    }

    pub(in crate::node_adapters::cnp::semantic) fn validate_installed_current_observation_data(
        &self,
        world: &WorldActivation,
        observation: &NativeSchedulingObservation,
    ) -> Result<(), OperationFailure> {
        self.try_validate_installed_current_observation_data(world, observation)
            .map_err(current_failure)
    }

    fn try_validate_installed_current_observation_data(
        &self,
        world: &WorldActivation,
        observation: &NativeSchedulingObservation,
    ) -> Result<(), RuntimeError> {
        let native = self
            .preparation
            .guard
            .custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let source = native
            .source
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let controller = native
            .controller
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let selected = native
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.installed_restoration.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let saved = selected
            .current_observations
            .last()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if saved.retained.as_ref() != Some(observation) {
            return Err(RuntimeError::InvalidReceipt);
        }
        selected
            .association
            .authenticate_original_current_observation_data(
                source.as_ref(),
                controller,
                Rc::as_ptr(&native.read_owner).cast(),
                world,
                saved.ordinal,
                observation,
            )
    }

    pub(in crate::node_adapters::cnp::semantic) fn has_installed_current_observation_data(
        &self,
    ) -> bool {
        self.preparation
            .guard
            .custody
            .as_ref()
            .and_then(|native| native.runtime.as_ref())
            .and_then(|runtime| runtime.installed_restoration.as_ref())
            .is_some_and(|selected| !selected.current_observations.is_empty())
    }

    pub(crate) fn original_current_observation_node_counter_scratch_data() -> usize {
        counter_scratch_data()
    }

    pub(crate) fn original_current_observation_node_reallocation_data(
        ordinal: u64,
    ) -> Result<usize, RuntimeError> {
        usize::try_from(ordinal)
            .map_err(|_| RuntimeError::ResourceLimit)?
            .checked_mul(size_of::<CurrentNodeObservation>())
            .ok_or(RuntimeError::ResourceLimit)
    }

    pub(crate) fn original_current_observation_node_growth_data() -> usize {
        size_of::<CurrentNodeObservation>() * 2
            + CURRENT_OBSERVATION_FAILURE.len() * 2
            + OriginalRestoredSchedulingObservationClaim::COMPLETION_FAILURE.len() * 2
    }
}

pub(super) const CURRENT_OBSERVATION_FAILURE: &str =
    "restored current observation did not complete its original proof fence";

fn current_failure(_: RuntimeError) -> OperationFailure {
    OperationFailure {
        effects: crate::node_contract::EffectKnowledge::Unknown,
        reason: CURRENT_OBSERVATION_FAILURE.into(),
    }
}

pub(super) fn slot_bytes_data() -> usize {
    size_of::<CurrentNodeObservation>()
}

pub(super) fn retained_data(
    state: &[CurrentNodeObservation],
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let mut bytes = 0usize;
    for attempt in state {
        for observation in [&attempt.retained, &attempt.returned] {
            if let Some(observation) = observation {
                bytes = storage::sum(&[bytes,
                    crate::node_contract::NodeRuntime::capture_scheduling_observation_storage_data(observation, maximum)?], maximum)?;
            }
        }
    }
    Ok(bytes)
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<CurrentNodeObservation>() * 2
        + size_of::<Vec<CurrentNodeObservation>>()
        + size_of::<Option<&CurrentNodeObservation>>()
        + size_of::<Option<&mut CurrentNodeObservation>>()
        + size_of::<Result<&CurrentNodeObservation, RuntimeError>>()
        + size_of::<Result<&mut CurrentNodeObservation, RuntimeError>>()
        + size_of::<std::slice::Iter<'static, CurrentNodeObservation>>()
        + size_of::<std::array::IntoIter<&'static Option<NativeSchedulingObservation>, 2>>()
        + size_of::<[&Option<NativeSchedulingObservation>; 2]>()
        + size_of::<Option<&NativeSchedulingObservation>>()
        + size_of::<Result<NativeSchedulingObservation, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Option<u64>>()
        + size_of::<Result<u64, RuntimeError>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&[u8]>()
        + size_of::<&OriginalRestoredSchedulingObservationClaim<'static>>()
        + size_of::<[usize; 22]>()
        + size_of::<Result<NativeSchedulingObservation, OperationFailure>>()
        + size_of::<Result<(), OperationFailure>>()
        + size_of::<Result<&mut crucible_node_transport::client::CnpController, RuntimeError>>()
        + size_of::<Option<&mut crucible_node_transport::client::CnpController>>()
        + size_of::<Result<&InstalledRestorationCustody, RuntimeError>>()
        + size_of::<Result<&mut InstalledRestorationCustody, RuntimeError>>()
        + size_of::<Option<&mut InstalledRestorationCustody>>()
        + size_of::<OperationFailure>()
        + size_of::<String>() * 2
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + crate::node_adapters::cnp::PacketCompleteSemanticSource::original_current_observation_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::{Phase, Position, Tick, U64, canonical};

    fn scheduling_data() -> NativeSchedulingObservation {
        let proof = canonical::content_ref(
            b"retained current-observation DATA",
            "application/octet-stream",
        )
        .expect("actual content identity");
        NativeSchedulingObservation {
            node: crucible_node_format::Id::new("current-node").unwrap(),
            owners: Vec::new(),
            reached: Position::new(Tick::new(0), U64::new(0), Phase::Reaction),
            closed_prefix: Position::new(Tick::new(0), U64::new(0), Phase::Reaction),
            bounds: Vec::new(),
            publications: Vec::new(),
            input_progress: None,
            external_inputs: Vec::new(),
            proof_ref: proof,
        }
    }

    #[test]
    fn actual_current_copy_banks_are_both_measured_and_partial_return_does_not_erase_saved() {
        let saved = scheduling_data();
        let returned = saved.clone();
        let saved_bytes =
            crate::node_contract::NodeRuntime::capture_scheduling_observation_storage_data(
                &saved,
                usize::MAX,
            )
            .expect("actual saved backing");
        let returned_bytes =
            crate::node_contract::NodeRuntime::capture_scheduling_observation_storage_data(
                &returned,
                usize::MAX,
            )
            .expect("independent return backing");
        let mut attempts = vec![CurrentNodeObservation {
            ordinal: 1,
            retained: Some(saved),
            returned: Some(returned),
        }];
        let complete = retained_data(&attempts, usize::MAX).expect("actual two-bank visitor");
        assert_eq!(complete, saved_bytes + returned_bytes);
        assert!(retained_data(&attempts, complete - 1).is_err());
        let actual_return = attempts[0].returned.take().expect("same returned owner");
        assert_eq!(retained_data(&attempts, saved_bytes), Ok(saved_bytes));
        assert!(attempts[0].retained.is_some());
        assert_eq!(actual_return, *attempts[0].retained.as_ref().unwrap());
        assert_eq!(attempts[0].ordinal, 1);
    }
}

impl crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityWalk
    for CurrentNodeObservation
{
    fn capacities(
        &self,
        depth: usize,
        sink: &mut dyn OriginalRestoredOwnerCapacitySink,
    ) -> Result<(), RuntimeError> {
        sink.visit_work(1)?;
        use crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityWalk;
        let Self {
            ordinal: _,
            retained,
            returned,
        } = self;
        retained.capacities(depth, sink)?;
        returned.capacities(depth, sink)
    }
}
