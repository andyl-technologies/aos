//! Selects one actual saved SDK frontier before authenticating a current proof.
//!
//! Selection compares completion DATA only. Every started or failed family
//! blocks the read, equal frontiers refuse, and a selected validator's failure
//! is final. An older Observe never repairs an advanced or corrupted branch.

use super::*;

#[path = "restored_checkpoint17/live_cache.rs"]
mod live_cache;
use crate::node_contract::WorldActivation;
use crucible_node_format::{ContentRef, U64};
use crucible_node_transport::{
    client::CnpController,
    reference_packet::{
        control::PacketNative5UnderlyingRecord,
        service::complete_restore::PacketNativeRestoredRecord,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Family {
    FirstObservation,
    Producer,
    RecurringObservation,
    InputReactive,
    Capture,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Candidate {
    family: Family,
    frontier: U64,
}

fn select_newest_data<const N: usize>(
    candidates: [Option<Candidate>; N],
) -> Result<Candidate, RuntimeError> {
    let mut selected: Option<Candidate> = None;
    for (index, entry) in candidates.iter().enumerate() {
        let Some(candidate) = *entry else {
            continue;
        };
        if candidate.frontier.get() == 0 {
            return Err(RuntimeError::InvalidReceipt);
        }
        // Every completed original has its own saved SDK cut. A duplicate is
        // inconsistent even when another family has already advanced further.
        for previous in candidates[..index].iter().flatten() {
            if previous.frontier == candidate.frontier {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        selected = match selected {
            Some(previous) if previous.frontier > candidate.frontier => Some(previous),
            _ => Some(candidate),
        };
    }
    selected.ok_or(RuntimeError::OwnerUnavailable)
}

pub(super) fn authenticate_world_record_data(
    source: &PacketCompleteSemanticSource,
    record: &PacketNativeRestoredRecord,
    world: &WorldActivation,
) -> Result<(), RuntimeError> {
    let installation = source.installation();
    let receipt = &record.native_receipt;
    let selected = &installation.binding.compatibility;
    if receipt.world != world.record().world_binding_hash
        || receipt.owner != installation.owner.owner.id
        || receipt.node != selected.node_id
        || receipt.world != installation.world_binding_hash
        || !world.record().owners.iter().any(|owner| {
            owner.owner == receipt.owner
                && owner.incarnation == receipt.incarnation
                && owner.generation == receipt.owner_generation
        })
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(())
}

impl PacketCompleteSemanticSource {
    /// Lends the uniquely newest completed checkpoint under an owning Source read.
    ///
    /// The caller holds the genuine original SourceRead and independently checks
    /// the native/current World and terminal read fence. No effect is authorized
    /// by this borrowed proof. All candidate loans end before the chosen callback;
    /// in particular a new Capture may borrow its own unused once owner mutably.
    ///
    /// # Errors
    /// Refuses a busy, failed or in-flight history, missing completion frontier,
    /// duplicate frontier, another World, changed SDK custody or invalid selected
    /// Source signature. A selected currentness failure never triggers fallback.
    pub(crate) fn with_latest_original_restored_checkpoint17_data<R>(
        &self,
        controller: &CnpController,
        world: &WorldActivation,
        key: &[u8; 32],
        inspect: impl FnOnce(&ContentRef, &ContentRef, U64) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        self.authenticate_unused_signed_observation17_owner_data()?;
        let first = self.original_first_observation_checkpoint_frontier17_data(controller)?;
        let producer = self.original_producer_checkpoint_frontier17_data()?;
        let recurring = self.original_current_observation_checkpoint_frontier17_data()?;
        let input = self.original_input_reactive_checkpoint_frontier17_data()?;
        let capture = self.original_restored_capture_checkpoint_frontier_data()?;
        let selected = select_newest_data([
            first.map(|frontier| Candidate {
                family: Family::FirstObservation,
                frontier,
            }),
            producer.map(|frontier| Candidate {
                family: Family::Producer,
                frontier,
            }),
            recurring.map(|frontier| Candidate {
                family: Family::RecurringObservation,
                frontier,
            }),
            input.map(|frontier| Candidate {
                family: Family::InputReactive,
                frontier,
            }),
            capture.map(|frontier| Candidate {
                family: Family::Capture,
                frontier,
            }),
        ])?;

        let result = match selected.family {
            Family::FirstObservation => self.with_original_first_observation_checkpoint17_data(
                controller,
                world,
                key,
                selected.frontier,
                inspect,
            ),
            Family::Producer => self.with_original_producer_checkpoint17_data(
                controller,
                world,
                key,
                selected.frontier,
                inspect,
            ),
            Family::RecurringObservation => self
                .with_original_current_observation_checkpoint17_data(
                    controller,
                    world,
                    key,
                    selected.frontier,
                    inspect,
                ),
            Family::InputReactive => self.with_original_input_reactive_checkpoint17_data(
                controller,
                world,
                key,
                selected.frontier,
                inspect,
            ),
            Family::Capture => self.with_original_restored_capture_checkpoint_data(
                controller,
                world,
                key,
                |record, model, frontier| {
                    if frontier != selected.frontier {
                        return Err(RuntimeError::InvalidReceipt);
                    }
                    inspect(record, model, frontier)
                },
            ),
        };
        self.storage_origin_with_error::<RuntimeError>()?;
        self.authenticate_unused_signed_observation17_owner_data()?;
        result
    }
}

/// Counts fixed selection and leaf dispatch views without allocating candidates.
pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<[Option<Candidate>; 5]>()
        + size_of::<Option<Candidate>>()
        + size_of::<Candidate>() * 2
        + size_of::<Result<Candidate, RuntimeError>>()
        + size_of::<Option<U64>>() * 5
        + size_of::<Result<Option<U64>, RuntimeError>>() * 5
        + size_of::<std::iter::Enumerate<std::slice::Iter<'static, Option<Candidate>>>>()
        + size_of::<std::slice::Iter<'static, Option<Candidate>>>()
        + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<Candidate>>>>()
        + size_of::<&Option<Candidate>>()
        + size_of::<&Candidate>()
        + size_of::<usize>()
        + size_of::<&ContentRef>() * 4
        + size_of::<&PacketNativeRestoredRecord>()
        + size_of::<&PacketNative5UnderlyingRecord>()
        + size_of::<[(Family, Option<U64>); 4]>()
        + size_of::<Option<(Family, Option<U64>)>>()
        + size_of::<std::array::IntoIter<(Family, Option<U64>), 4>>()
        + size_of::<&WorldActivation>()
        + size_of::<&[u8; 32]>()
        + size_of::<U64>()
        + size_of::<Result<(), RuntimeError>>()
        + PacketCompleteSemanticSource::original_first_observation_checkpoint17_counter_scratch_data()
        + PacketCompleteSemanticSource::original_producer_checkpoint17_counter_scratch_data()
        + PacketCompleteSemanticSource::original_current_observation_checkpoint17_counter_scratch_data()
        + super::restored_input_reactive17::counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(family: Family, frontier: u64) -> Option<Candidate> {
        Some(Candidate {
            family,
            frontier: frontier.into(),
        })
    }

    #[test]
    fn selection_uses_the_saved_frontier_instead_of_family_precedence() {
        let families = [
            Family::FirstObservation,
            Family::Producer,
            Family::RecurringObservation,
            Family::InputReactive,
            Family::Capture,
        ];
        for (latest, family) in families.into_iter().enumerate() {
            let candidates: [Option<Candidate>; 5] = std::array::from_fn(|index| {
                candidate(
                    families[index],
                    if index == latest {
                        100
                    } else {
                        index as u64 + 1
                    },
                )
            });
            assert_eq!(select_newest_data(candidates).unwrap().family, family);
        }
    }

    #[test]
    fn older_duplicate_cuts_refuse_beneath_an_already_newer_checkpoint() {
        assert_eq!(
            select_newest_data([
                candidate(Family::FirstObservation, 100),
                candidate(Family::Producer, 8),
                candidate(Family::RecurringObservation, 8),
            ]),
            Err(RuntimeError::InvalidReceipt),
        );
    }

    #[test]
    fn every_pair_of_family_positions_refuses_duplicate_nonmaximum_cuts() {
        let families = [
            Family::FirstObservation,
            Family::Producer,
            Family::RecurringObservation,
            Family::InputReactive,
            Family::Capture,
        ];
        for left in 0..families.len() {
            for right in left + 1..families.len() {
                let candidates: [Option<Candidate>; 5] = std::array::from_fn(|index| {
                    candidate(
                        families[index],
                        if index == left || index == right {
                            8
                        } else {
                            100 + index as u64
                        },
                    )
                });
                assert_eq!(
                    select_newest_data(candidates),
                    Err(RuntimeError::InvalidReceipt),
                    "duplicate positions {left}/{right}"
                );
            }
        }
    }

    #[test]
    fn conflicting_frontiers_refuse_instead_of_tie_breaking() {
        assert_eq!(
            select_newest_data([
                candidate(Family::FirstObservation, 8),
                candidate(Family::InputReactive, 8),
            ]),
            Err(RuntimeError::InvalidReceipt)
        );
        assert_eq!(
            select_newest_data([
                candidate(Family::Capture, 0),
                candidate(Family::Producer, 10),
            ]),
            Err(RuntimeError::InvalidReceipt)
        );
        assert_eq!(
            select_newest_data([None; 5]),
            Err(RuntimeError::OwnerUnavailable)
        );
    }
}

impl PacketCompleteSemanticSource {
    /// Lends the unique newest actual typed checkpoint beneath its current owner.
    ///
    /// No typed model is decoded or copied. Current SDK/native/Source predicates
    /// precede the callback and repeat afterward in that exact selected family.
    ///
    /// # Errors
    /// Refuses every incomplete/failed history, conflicting saved frontier,
    /// foreign World, invalid selected proof or current-owner refusal.
    pub(crate) fn with_latest_original_restored_typed_checkpoint17_data<R>(
        &self,
        controller: &CnpController,
        world: &WorldActivation,
        key: &[u8; 32],
        inspect: impl FnOnce(
            &PacketNativeRestoredRecord,
            &PacketNative5UnderlyingRecord,
            &ContentRef,
            U64,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        self.authenticate_unused_signed_observation17_owner_data()?;
        let first = self.original_first_observation_checkpoint_frontier17_data(controller)?;
        let producer = self.original_producer_checkpoint_frontier17_data()?;
        let recurring = self.original_current_observation_checkpoint_frontier17_data()?;
        let input = self.original_input_reactive_checkpoint_frontier17_data()?;
        let capture = self.original_restored_capture_checkpoint_frontier_data()?;
        let selected = select_newest_data([
            first.map(|frontier| Candidate {
                family: Family::FirstObservation,
                frontier,
            }),
            producer.map(|frontier| Candidate {
                family: Family::Producer,
                frontier,
            }),
            recurring.map(|frontier| Candidate {
                family: Family::RecurringObservation,
                frontier,
            }),
            input.map(|frontier| Candidate {
                family: Family::InputReactive,
                frontier,
            }),
            capture.map(|frontier| Candidate {
                family: Family::Capture,
                frontier,
            }),
        ])?;
        let result = match selected.family {
            Family::FirstObservation => self
                .with_original_first_observation_typed_checkpoint17_data(
                    controller,
                    world,
                    key,
                    selected.frontier,
                    true,
                    inspect,
                ),
            Family::Producer => self.with_original_producer_typed_checkpoint17_data(
                controller,
                world,
                key,
                selected.frontier,
                true,
                inspect,
            ),
            Family::RecurringObservation => self
                .with_original_current_observation_typed_checkpoint17_data(
                    controller,
                    world,
                    key,
                    selected.frontier,
                    true,
                    inspect,
                ),
            Family::InputReactive => self.with_original_input_reactive_typed_checkpoint17_data(
                controller,
                world,
                key,
                selected.frontier,
                true,
                inspect,
            ),
            Family::Capture => self.with_original_restored_capture_typed_checkpoint_data(
                controller,
                world,
                key,
                |record, underlying, measurement, frontier| {
                    if frontier != selected.frontier {
                        return Err(RuntimeError::InvalidReceipt);
                    }
                    inspect(record, underlying, measurement, frontier)
                },
            ),
        };
        self.storage_origin_with_error::<RuntimeError>()?;
        self.authenticate_unused_signed_observation17_owner_data()?;
        result
    }

    /// Lends immutable typed DATA selected by an authenticated bridge's old cut.
    ///
    /// This deliberately asserts no old SDK currency. The genuine current
    /// administrative bridge surrounds this callback and authenticates its own
    /// exact retained precheckpoint identities, unchanged native model, actual
    /// SDK final frontier and private signature before and after lending them.
    /// Matching these portable references alone grants neither that bridge nor
    /// SourceRead, a native action, or allocation permission.
    ///
    /// # Errors
    /// Refuses missing/ambiguous retained bodies, conflicting full references,
    /// invalid old Source signature, another original SDK pair/World or callback.
    pub(crate) fn with_original_retained_checkpoint17_at_frontier_data<R>(
        &self,
        controller: &CnpController,
        world: &WorldActivation,
        key: &[u8; 32],
        measurement: &ContentRef,
        model: &ContentRef,
        frontier: U64,
        inspect: impl FnOnce(
            &PacketNativeRestoredRecord,
            &PacketNative5UnderlyingRecord,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        self.authenticate_unused_signed_observation17_owner_data()?;
        let candidates = [
            (
                Family::FirstObservation,
                self.original_first_observation_checkpoint_frontier17_data(controller)?,
            ),
            (
                Family::Producer,
                self.original_producer_checkpoint_frontier17_data()?,
            ),
            (
                Family::RecurringObservation,
                self.original_current_observation_checkpoint_frontier17_data()?,
            ),
            (
                Family::InputReactive,
                self.original_input_reactive_checkpoint_frontier17_data()?,
            ),
        ];
        let mut matches = candidates
            .into_iter()
            .filter(|(_, actual)| *actual == Some(frontier));
        let (family, _) = matches.next().ok_or(RuntimeError::OwnerUnavailable)?;
        if matches.next().is_some() {
            return Err(RuntimeError::InvalidReceipt);
        }
        let checked = |record: &PacketNativeRestoredRecord,
                       underlying: &PacketNative5UnderlyingRecord,
                       actual_measurement: &ContentRef,
                       actual_frontier: U64| {
            if actual_frontier != frontier
                || actual_measurement != measurement
                || &record.native_receipt.native_record != model
            {
                return Err(RuntimeError::InvalidReceipt);
            }
            inspect(record, underlying)
        };
        let result = match family {
            Family::FirstObservation => self
                .with_original_first_observation_typed_checkpoint17_data(
                    controller, world, key, frontier, false, checked,
                ),
            Family::Producer => self.with_original_producer_typed_checkpoint17_data(
                controller, world, key, frontier, false, checked,
            ),
            Family::RecurringObservation => self
                .with_original_current_observation_typed_checkpoint17_data(
                    controller, world, key, frontier, false, checked,
                ),
            Family::InputReactive => self.with_original_input_reactive_typed_checkpoint17_data(
                controller, world, key, frontier, false, checked,
            ),
            Family::Capture => Err(RuntimeError::ForeignAuthority),
        };
        self.storage_origin_with_error::<RuntimeError>()?;
        self.authenticate_unused_signed_observation17_owner_data()?;
        result
    }
}

/// Compares concrete retained model DATA without widening the provider enum.
pub(super) fn same_underlying_data(
    left: &PacketNative5UnderlyingRecord,
    right: &PacketNative5UnderlyingRecord,
) -> bool {
    match (left, right) {
        (
            PacketNative5UnderlyingRecord::Producer(left),
            PacketNative5UnderlyingRecord::Producer(right),
        ) => left == right,
        (
            PacketNative5UnderlyingRecord::Reactive(left),
            PacketNative5UnderlyingRecord::Reactive(right),
        ) => left == right,
        _ => false,
    }
}
