//! Holds the genuine serving Root journals through the saved Source-floor join.
//!
//! Complete saved history and exact current Tree comparison share the existing
//! engines. Distinct native name/witness/location and Root/Controller/clock
//! posts remain owed after any reached failure. This stage cannot commit a new
//! D floor or dispose the enclosing lifecycle without the genuine six owners.

use super::{
    RootDeleteChallengeOriginalsV1, RootDeleteControllerCurrentOriginalV1, RootDeleteErrorV1,
    RootDeleteSourceCurrentOriginalV1,
};
use crate::controller_resource_reservation::{ResourceReservationErrorV1, RootDeleteChunkPostsV1};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::{
    Journal, JournalError, ProtectedJournalCurrentnessOriginalsV1, ProtectedJournalNamesV1,
};
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, POLICY_STATE_JOURNAL, PROTECTED_POLICY_ROOT,
    policy_authority_journal_limits, policy_state_journal_limits,
};
use crate::policy_compiler::{
    RetainedKernelPairedClockAttemptV1,
    create_storage_current::pins::RootCurrentPinsStateV1,
    root_current_writers::RootCreateStorageCurrentWritersV1,
    source_genesis_root::{
        RootSavedFloorComparisonErrorV1, RootSavedSourceFloorDataV1, compare_saved_source_floor_v1,
    },
};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use std::error::Error;
use std::path::Path;

type WitnessOriginal =
    aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1<JournalError>;

#[derive(Default)]
struct RootFloorPairSampleV1 {
    names_original: [ProtectedJournalCurrentnessOriginalsV1; 2],
    witness: [WitnessOriginal; 2],
    location_original: [ProtectedJournalCurrentnessOriginalsV1; 2],
    names: [Option<Result<ProtectedJournalNamesV1, JournalError>>; 2],
    locations: [Option<Result<(), JournalError>>; 2],
    entered: bool,
}

impl RootFloorPairSampleV1 {
    fn fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        let mut demand = ResourceVector::ZERO;
        for name in [POLICY_AUTHORITY_JOURNAL, POLICY_STATE_JOURNAL] {
            let one = ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
                Path::new(PROTECTED_POLICY_ROOT),
                name,
            )?;
            demand = demand
                .checked_add(one)
                .and_then(|demand| demand.checked_add(one))
                .map_err(|_| JournalError::JournalTooLarge)?;
        }
        let witness =
            WitnessOriginal::receiving_footprint_v1().ok_or(JournalError::JournalTooLarge)?;
        let bytes = witness
            .memory_bytes
            .checked_mul(2)
            .ok_or(JournalError::JournalTooLarge)?;
        let bytes = u64::try_from(bytes).map_err(|_| JournalError::JournalTooLarge)?;
        demand
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    fn observe_once(
        &mut self,
        writers: &mut RootCreateStorageCurrentWritersV1,
    ) -> Result<(), JournalError> {
        if self.entered {
            return Err(JournalError::ProtectedBoundary);
        }
        self.entered = true;
        let (authority, policy) = writers.authority_and_policy()?;
        // These exact native engines are shared with the existing Root history
        // owner. Both paths and locations are independently observed even when
        // a preceding name/witness result fails.
        for (index, journal) in [&*authority, policy].into_iter().enumerate() {
            self.names[index] = Some(journal.observe_held_physical_names_retaining_v1(
                &mut self.names_original[index],
                &mut self.witness[index],
            ));
        }
        self.locations[0] = Some(authority.require_protected_location_retaining(
            Path::new(PROTECTED_POLICY_ROOT),
            POLICY_AUTHORITY_JOURNAL,
            0,
            policy_authority_journal_limits(),
            &mut self.location_original[0],
        ));
        self.locations[1] = Some(policy.require_protected_location_retaining(
            Path::new(PROTECTED_POLICY_ROOT),
            POLICY_STATE_JOURNAL,
            0,
            policy_state_journal_limits(),
            &mut self.location_original[1],
        ));
        if self.failure().is_none()
            && self.names.iter().all(|v| matches!(v, Some(Ok(_))))
            && self.locations.iter().all(|v| matches!(v, Some(Ok(()))))
        {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        for index in 0..2 {
            if let Some(cause) = self.names_original[index].failure() {
                return Some(cause);
            }
            if let Some(cause) = self.witness[index].failure() {
                return Some(cause);
            }
            if let Some(cause) = cause(&self.names[index]) {
                return Some(cause);
            }
        }
        for index in 0..2 {
            if let Some(cause) = self.location_original[index].failure() {
                return Some(cause);
            }
            if let Some(cause) = cause(&self.locations[index]) {
                return Some(cause);
            }
        }
        None
    }
}

#[derive(Clone, Copy)]
enum First {
    Geometry,
    Permit,
    Arm,
    ClockBefore,
    Before,
    NamesBefore,
    Pins,
    Compare,
    NamesAfter,
    NamesChanged,
    After,
    ClockAfter,
    Reentry,
}

#[derive(Default)]
pub(crate) struct RootDeleteFloorOriginalV1 {
    final_read: bool,
    geometry: Option<Result<ResourceVector, JournalError>>,
    permit: Option<Result<(), ResourceReservationErrorV1>>,
    posts: RootDeleteChunkPostsV1,
    arm: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    names_before: RootFloorPairSampleV1,
    names_before_result: Option<Result<(), JournalError>>,
    names_after: RootFloorPairSampleV1,
    names_after_result: Option<Result<(), JournalError>>,
    names_binding: Option<Result<(), JournalError>>,
    before_original: RetainedKernelPairedClockAttemptV1,
    before_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_binding: Option<Result<(), JournalError>>,
    after_original: RetainedKernelPairedClockAttemptV1,
    after_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_binding: Option<Result<(), JournalError>>,
    pin_check: Option<
        Result<(), crate::policy_compiler::create_storage_current::pins::RootServingPinsErrorV1>,
    >,
    floor: Option<Result<RootSavedSourceFloorDataV1, RootSavedFloorComparisonErrorV1>>,
    entered: bool,
    native_entered: bool,
    complete: bool,
    first: Option<First>,
    closed: Option<RootDeleteErrorV1>,
}

impl RootDeleteFloorOriginalV1 {
    pub(super) fn select_final_read_once_v2(&mut self,
        initial: &super::initial_inventory::RootDeleteInitialInventoryOriginalV2,
        fresh: &super::final_inventory::RootDeleteFreshInventoryOriginalV2,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.final_read || self.entered || self.first.is_some()
            || initial.completed_ack_bytes_v2().is_err() || fresh.require_inputs_complete_v2().is_err()
        {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.final_read = true;
        Ok(())
    }

    pub(crate) fn is_final_read_v2(&self) -> bool {
        self.final_read
    }

    pub(crate) fn observe_with_serving_once_v1(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
        controller: &RootDeleteControllerCurrentOriginalV1,
        source: &RootDeleteSourceCurrentOriginalV1,
        writers: &mut RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        // This visits only the already-resident logical map; no native read,
        // model clone or variable allocation precedes the same-R full prepay.
        self.geometry = Some(actual_map_geometry_v1(writers));
        if self.geometry.as_ref().is_none_or(Result::is_err) {
            self.first = Some(First::Geometry);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.permit = Some(flight.admit_delete_floor_v1(challenge, controller, source, self));
        if !matches!(self.permit, Some(Ok(()))) {
            self.first = Some(First::Permit);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.native_entered = true;
        let primary = self.observe_inner(flight, challenge, source, writers, pins);
        // Actual journal native posts, then actual Root/Controller posts and
        // final paired clock are all independently attempted after entry.
        self.names_after_result = Some(self.names_after.observe_once(writers));
        if !matches!(self.names_after_result, Some(Ok(()))) {
            self.first.get_or_insert(First::NamesAfter);
        }
        self.names_binding = Some((|| {
            for index in 0..2 {
                if positive(&self.names_before.names[index])?
                    != positive(&self.names_after.names[index])?
                {
                    return Err(JournalError::ProtectedBoundary);
                }
            }
            Ok(())
        })());
        if !matches!(self.names_binding, Some(Ok(()))) {
            self.first.get_or_insert(First::NamesChanged);
        }
        self.after = Some(self.posts.observe_after_once_v1(flight, challenge));
        if !matches!(self.after, Some(Ok(()))) {
            self.first.get_or_insert(First::After);
        }
        self.after_clock = Some(self.after_original.observe_once(None));
        self.after_binding = Some((|| {
            let before = *positive(&self.before_clock)?;
            let after = *positive(&self.after_clock)?;
            before
                .validate_later_sample(after)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            challenge.require_current_clock_v1(after)
        })());
        if !matches!(self.after_binding, Some(Ok(()))) {
            self.first.get_or_insert(First::ClockAfter);
        }
        if primary.is_err() || self.first.is_some() {
            return Err(RootDeleteErrorV1::Opening);
        }
        self.complete = true;
        Ok(())
    }

    fn observe_inner(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
        source: &RootDeleteSourceCurrentOriginalV1,
        writers: &mut RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
    ) -> Result<(), RootDeleteErrorV1> {
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(challenge, &mut self.posts));
        self.require(matches!(self.arm, Some(Ok(()))), First::Arm)?;
        self.before_clock = Some(self.before_original.observe_once(None));
        self.before_binding = Some(
            positive(&self.before_clock)
                .and_then(|clock| challenge.require_current_clock_v1(*clock)),
        );
        self.before = Some(self.posts.observe_before_once_v1(flight, challenge));
        self.require(
            matches!(self.before_binding, Some(Ok(()))),
            First::ClockBefore,
        )?;
        self.require(matches!(self.before, Some(Ok(()))), First::Before)?;
        self.names_before_result = Some(self.names_before.observe_once(writers));
        self.require(
            matches!(self.names_before_result, Some(Ok(()))),
            First::NamesBefore,
        )?;
        let (_, policy) = writers
            .authority_and_policy()
            .map_err(|_| RootDeleteErrorV1::Opening)?;
        self.pin_check = Some(pins.require_serving_policy_v1(policy));
        self.require(matches!(self.pin_check, Some(Ok(()))), First::Pins)?;
        let tuple = match pins.saved_genesis_role_tuple_v1() {
            Ok(tuple) => tuple,
            Err(cause) => {
                self.pin_check = Some(Err(crate::policy_compiler::create_storage_current::pins::RootServingPinsErrorV1::Incomplete(cause)));
                self.first = Some(First::Pins);
                return Err(RootDeleteErrorV1::Opening);
            }
        };
        let fields = source.verified_fields_v1()?;
        let (authority, _) = writers
            .authority_and_policy()
            .map_err(|_| RootDeleteErrorV1::Opening)?;
        self.floor = Some(compare_saved_source_floor_v1(authority, tuple, fields));
        self.require(matches!(self.floor, Some(Ok(_))), First::Compare)
    }

    fn require(&mut self, positive: bool, stage: First) -> Result<(), RootDeleteErrorV1> {
        if positive {
            Ok(())
        } else {
            self.first.get_or_insert(stage);
            Err(RootDeleteErrorV1::Opening)
        }
    }

    pub(crate) fn receiving_demand_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if !self.entered || self.permit.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.receiving_recipe_v1()
    }

    pub(crate) fn retained_receiving_demand_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if !self.complete || self.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.receiving_recipe_v1()
    }

    fn receiving_recipe_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let pair = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or_else(invalid)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(pair.checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let names = RootFloorPairSampleV1::fixed_demand_v1().map_err(|_| invalid())?;
        let clock_names = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|names| names.checked_mul(2))
            .and_then(|names| u64::try_from(names).ok())
            .ok_or_else(invalid)?;
        let model = *positive(&self.geometry).map_err(|_| invalid())?;
        RootDeleteChunkPostsV1::fixed_demand_v1()?
            .checked_add(names)?
            .checked_add(names)?
            .checked_add(model)?
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, bytes)
                    .with(D::MetadataEntries, clock_names)
                    .with(
                        D::OpenFiles,
                        2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64,
                    ),
            )
            .map_err(Into::into)
    }

    pub(super) fn financial_failure_is_selected_v1(&self) -> bool {
        matches!(self.first, Some(First::Permit))
            || matches!(self.first, Some(First::Arm)) && self.posts.funding_failed_v1()
    }

    pub(super) fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        match self.first? {
            First::Before | First::After => self.posts.property_failure_view_v1(self.failure()?),
            _ => None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Geometry => cause(&self.geometry),
            First::Permit => cause(&self.permit),
            First::Arm | First::Before => self
                .posts
                .before_failure_v1()
                .or_else(|| cause(&self.arm))
                .or_else(|| cause(&self.before)),
            First::ClockBefore => self
                .before_original
                .failure()
                .or_else(|| cause(&self.before_clock))
                .or_else(|| cause(&self.before_binding)),
            First::ClockAfter => self
                .after_original
                .failure()
                .or_else(|| cause(&self.after_clock))
                .or_else(|| cause(&self.after_binding)),
            First::NamesBefore => self
                .names_before
                .failure()
                .or_else(|| cause(&self.names_before_result)),
            First::NamesAfter => self
                .names_after
                .failure()
                .or_else(|| cause(&self.names_after_result)),
            First::NamesChanged => cause(&self.names_binding),
            First::Pins => cause(&self.pin_check),
            First::Compare => cause(&self.floor),
            First::After => self.posts.after_failure_v1().or_else(|| cause(&self.after)),
            First::Reentry => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

fn actual_map_geometry_v1(
    writers: &mut RootCreateStorageCurrentWritersV1,
) -> Result<ResourceVector, JournalError> {
    let (authority, _) = writers.authority_and_policy()?;
    let mut count = 0_usize;
    let mut bytes = 0_usize;
    for (_, key, value) in authority.all_records() {
        count = count.checked_add(1).ok_or(JournalError::JournalTooLarge)?;
        bytes = bytes
            .checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or(JournalError::JournalTooLarge)?;
    }
    // Complete old family validation clones the actual logical map; complete
    // project selection also builds its actual typed archive map. A namespace
    // row accounts for at most one clone entry and one typed family entry at
    // that peak. Fixed receipt/intent codecs are bounded by their actual row
    // bytes; the enclosing fixed carrier pays their headers and signature work.
    let nodes = aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<
        (crate::journal::RecordNamespace, Vec<u8>),
        Vec<u8>,
    >(count)
    .ok_or(JournalError::JournalTooLarge)?;
    let receipt = aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDecodeOriginalsV1::<SourceGenesisErrorV1>::fixed_footprint_v1()
        .ok_or(JournalError::JournalTooLarge)?.0;
    let phase = aos_sandbox_ledger_replay::replay::phase_records::first_source_successor_fixed_codec_peak_bytes_v1()
        .ok_or(JournalError::JournalTooLarge)?;
    let fixed_models = std::mem::size_of::<RootSavedSourceFloorDataV1>().checked_mul(4)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<aos_sandbox_ledger_replay::hierarchy::graph::SandboxTreeV1>().checked_mul(4)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<crate::policy_compiler::source_genesis_root::RootRolePinsDataV1>().checked_mul(4)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(4)?))
        .and_then(|bytes| bytes.checked_add(4 * 72))
        .and_then(|bytes| bytes.checked_add(receipt))
        .and_then(|bytes| bytes.checked_add(phase)).ok_or(JournalError::JournalTooLarge)?;
    let peak = bytes
        .checked_add(nodes)
        .and_then(|bytes| bytes.checked_mul(16))
        .and_then(|bytes| bytes.checked_add(fixed_models))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(JournalError::JournalTooLarge)?;
    let entries = count
        .checked_mul(2)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(JournalError::JournalTooLarge)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, peak)
        .with(D::MetadataEntries, entries))
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
