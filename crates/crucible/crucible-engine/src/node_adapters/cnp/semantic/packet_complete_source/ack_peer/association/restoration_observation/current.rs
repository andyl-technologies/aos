//! Retains fresh ordinary Observe originals without renewing imported ancestry.
//!
//! A genuine Window claim admits each independent row before allocation. The
//! Source keeps every partial SDK/proof/model owner, authenticates the actual
//! fresh original and ACK frontier, and completes its own native read fence.

use super::*;
use crate::node_admission::{
    OriginalRestoredSchedulingObservationClaim,
    OriginalRestoredSchedulingObservationConstructionData,
};
use crucible_node_transport::{
    bodies::ObserveRequest,
    client::{OriginalRestoredSuffixBody, OriginalRestoredSuffixHostAttempt},
    reference_packet::service::{
        PacketNative5SourceLaunch,
        native_startup::{
            original_native_restored_suffix_observation_counter_scratch_data,
            original_native_restored_suffix_observation_storage_data,
        },
    },
};
use std::{cell::RefCell, thread::ThreadId};

#[path = "current/checkpoint_cache17.rs"]
mod checkpoint_cache17;
#[path = "current/construction.rs"]
mod construction;
#[path = "current/effect.rs"]
mod effect;
#[path = "current/validation.rs"]
mod validation;

#[path = "current/capacities.rs"]
mod capacities;

pub(crate) use validation::OriginalSourceRestoredObservationCompletion;

const REQUEST_PREFIX: &str = "cnp-restored-current-";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Started,
    Published,
    Verified,
    Failed,
}

struct CurrentObservationAttempt {
    row: OriginalRestoredSchedulingObservationConstructionData,
    id: Option<Id>,
    body: Option<ObserveRequest>,
    sdk: Option<OriginalRestoredSuffixHostAttempt>,
    measurement: Option<ContentRef>,
    record: Option<PacketNativeRestoredRecord>,
    underlying: Option<PacketNative5UnderlyingRecord>,
    scheduling: Option<NativeSchedulingObservation>,
    previous: [u8; 32],
    signature: Option<[u8; 32]>,
    stage: Stage,
}

pub(in super::super) struct CurrentObservationHistory {
    process: u32,
    thread: ThreadId,
    failed: bool,
    attempts: Vec<CurrentObservationAttempt>,
}

impl CurrentObservationHistory {
    pub(in super::super) fn new() -> Self {
        Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            failed: false,
            attempts: Vec::new(),
        }
    }

    pub(in super::super) fn is_used_data(&self) -> bool {
        self.failed || !self.attempts.is_empty() || self.attempts.capacity() != 0
    }

    fn poison_next_data(&mut self, ordinal: u64) -> Result<(), RuntimeError> {
        self.authenticate_origin_data()?;
        if self.failed
            || u64::try_from(self.attempts.len())
                .map_err(|_| RuntimeError::ResourceLimit)?
                .checked_add(1)
                != Some(ordinal)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.failed = true;
        Ok(())
    }

    fn authenticate_origin_data(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn retained_heap_bytes_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::sum_with_error;
        let mut bytes = self
            .attempts
            .capacity()
            .checked_mul(size_of::<CurrentObservationAttempt>())
            .ok_or_else(|| E::limit("current observation slot capacities"))?;
        if bytes > maximum {
            return Err(E::limit("current observation slot capacities"));
        }
        for attempt in &self.attempts {
            if let Some(id) = &attempt.id {
                bytes = sum_with_error::<E, _>([bytes, id.allocated_capacity()], maximum)?;
            }
            if let Some(body) = &attempt.body {
                let facts = RetainedRestorationObservationData::Body(body)
                    .original_retained_metadata_facts()
                    .map_err(E::unknown)?;
                bytes = sum_with_error::<E, _>([bytes,
                    PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(&facts, maximum)?], maximum)?;
            }
            if let Some(sdk) = &attempt.sdk {
                let facts = sdk.retained_metadata_data().map_err(E::unknown)?;
                bytes = sum_with_error::<E, _>([bytes,
                    PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(&facts, maximum)?], maximum)?;
            }
            if let Some(measurement) = &attempt.measurement {
                bytes = sum_with_error::<E, _>(
                    [
                        bytes,
                        NodeRuntime::capture_reference_storage(measurement)
                            .map_err(|_| E::limit("current observation full reference"))?,
                    ],
                    maximum,
                )?;
            }
            if let Some(record) = &attempt.record {
                let facts = restoration_activation_retained_native_evidence_data(
                    record,
                    attempt.underlying.as_ref(),
                )
                .map_err(E::unknown)?;
                bytes = sum_with_error::<E, _>([bytes,
                    PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(&facts, maximum)?], maximum)?;
            } else if attempt.underlying.is_some() {
                return Err(E::unknown("current observation model lacks owning record"));
            }
            if let Some(scheduling) = &attempt.scheduling {
                bytes = sum_with_error::<E, _>(
                    [
                        bytes,
                        NodeRuntime::capture_scheduling_observation_storage_data(
                            scheduling, maximum,
                        )
                        .map_err(|_| E::limit("current observation scheduling backing"))?,
                    ],
                    maximum,
                )?;
            }
        }
        Ok(bytes)
    }
}

struct AttemptGuard<'a>(&'a RefCell<CurrentObservationHistory>);

impl Drop for AttemptGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut history) = self.0.try_borrow_mut() {
            if let Some(attempt) = history.attempts.last_mut()
                && attempt.stage != Stage::Verified
            {
                attempt.stage = Stage::Failed;
                history.failed = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_adapters::cnp::semantic::packet_complete_source::tests as fixture;
    use std::rc::Rc;

    #[test]
    fn actual_producer_and_reactive_sources_keep_failed_current_capacity_and_banks() {
        for reactive in [false, true] {
            let installed = fixture::coordinator();
            let source = Rc::new(if reactive {
                PacketCompleteSemanticSource::new_reactive_for_collecting_world(
                    fixture::installation(&installed, 1),
                    fixture::reactive(&installed, 1),
                    installed,
                    fixture::storage_selection(),
                )
                .expect("actual reactive Source constructor")
            } else {
                PacketCompleteSemanticSource::new_producer_for_collecting_world(
                    fixture::installation(&installed, 0),
                    fixture::producer(),
                    installed,
                    fixture::storage_selection(),
                )
                .expect("actual producer Source constructor")
            });
            OriginalAckPeerAssociation::reserve_into(
                256,
                &mut source.ack_peer_association.borrow_mut(),
            )
            .expect("actual original banks");
            let before = source
                .original_complete_boot_association_storage_data_with_error::<RuntimeError>(
                    usize::MAX,
                )
                .expect("actual retained old banks");
            {
                let association = source.ack_peer_association.borrow();
                let history = &association
                    .as_ref()
                    .expect("actual association")
                    .current_observations;
                {
                    let mut state = history.borrow_mut();
                    state
                        .poison_next_data(1)
                        .expect("actual irreversible first gate");
                    state
                        .attempts
                        .try_reserve_exact(1)
                        .expect("actual spare attempt bank");
                    assert!(state.is_used_data());
                    assert!(state.poison_next_data(1).is_err());
                    assert!(state.poison_next_data(2).is_err());
                }
                drop(AttemptGuard(history));
                let state = history.borrow();
                assert!(state.failed);
                assert!(state.attempts.is_empty());
                let extent = state
                    .retained_heap_bytes_with_error::<RuntimeError>(usize::MAX)
                    .expect("actual spare capacity census");
                assert!(extent >= size_of::<CurrentObservationAttempt>());
                assert_eq!(
                    state.retained_heap_bytes_with_error::<RuntimeError>(extent),
                    Ok(extent)
                );
                assert!(
                    state
                        .retained_heap_bytes_with_error::<RuntimeError>(extent - 1)
                        .is_err()
                );
            }
            let after = source
                .original_complete_boot_association_storage_data_with_error::<RuntimeError>(
                    usize::MAX,
                )
                .expect("failed actual owner remains observable");
            assert!(after > before);
            assert_eq!(
                source.original_complete_boot_association_storage_data_with_error::<RuntimeError>(
                    after
                ),
                Ok(after)
            );
            assert!(
                source
                    .original_complete_boot_association_storage_data_with_error::<RuntimeError>(
                        after - 1
                    )
                    .is_err()
            );
            assert!(source.authenticate_current_native().is_err());
        }
    }

    #[test]
    fn foreign_origin_cannot_spend_the_actual_current_history() {
        let mut history = CurrentObservationHistory::new();
        let actual = history.process;
        history.process = actual.wrapping_add(1);
        assert!(history.poison_next_data(1).is_err());
        assert!(!history.failed);
        assert_eq!(history.attempts.capacity(), 0);
        history.process = actual;
        assert!(history.poison_next_data(1).is_ok());
        assert!(history.poison_next_data(1).is_err());
    }
}

#[path = "current/capture_history.rs"]
pub(in super::super) mod capture_history;

#[path = "current/settled_logical.rs"]
mod settled_logical;

#[path = "current/checkpoint17.rs"]
mod checkpoint17;
#[path = "current/typed_checkpoint17.rs"]
mod typed_checkpoint17;
