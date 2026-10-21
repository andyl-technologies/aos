//! Checks complete Root genesis and successor history on the same held index.
//!
//! The actual native Authority owns the writer, independent pins and every
//! reached per-intent name observation. It borrows the existing complete
//! canonical state instead of cloning another BTree map. Ordering, all generic
//! namespaces and each original native capacity gate remain unchanged.

use std::error::Error;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_broker::domain_transaction_custody::capacity_records::lookup_capacity_record_v1;
use aos_sandbox_model::{RecordNamespace, ResourceDimension as D, ResourceVector};
use aos_sandbox_ledger_replay::replay::root_genesis_records::{
    FLOOR_PREFIX, INSTANCE_KEY, INTENT_PREFIX, PINS_KEY, RootSourceGenesisIntentRecordV1,
    SourceHierarchyFloorRecordV1, decode_instance, project_key,
};
use aos_sandbox_ledger_replay::replay::root_successor;
use aos_sandbox_protocol::domain_ledger::capacity::{
    GlobalCapacityReservationPurposeV1, reservation_id,
};
use aos_sandbox_protocol::domain_ledger::capacity_family::legacy_capacity_ids_for_purpose;

use crate::native::PolicyNativeJournalErrorV1;
use crate::native::journal::RootPolicyJournalV1;

use super::capacity;
use super::error::RootAuthorityErrorV1;
use super::names::{RootAuthorityNameRecipeV1, RootAuthorityNamesOriginalV1};
use super::pins::RootAuthorityPinsOriginalV1;

const MAXIMUM_PROJECTS: usize = 4096;

pub(super) struct RootAuthorityHistoryOriginalV1 {
    geometry: Option<Result<ResourceVector, RootAuthorityErrorV1>>,
    admission: Option<Result<(), PolicyNativeJournalErrorV1>>,
    allocation: Option<Result<(), std::collections::TryReserveError>>,
    native: Vec<RootAuthorityNamesOriginalV1>,
    outcome: Option<Result<(), RootAuthorityErrorV1>>,
    entered: bool,
    reentered: bool,
}

impl RootAuthorityHistoryOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            geometry: None,
            admission: None,
            allocation: None,
            native: Vec::new(),
            outcome: None,
            entered: false,
            reentered: false,
        }
    }

    fn demand_v1(journal: &RootPolicyJournalV1) -> Result<ResourceVector, RootAuthorityErrorV1> {
        let overflow = || PolicyNativeJournalErrorV1::geometry();
        let count = journal
            .records(RecordNamespace::DesiredState)
            .filter(|(key, _)| key.starts_with(INTENT_PREFIX))
            .count();
        // These destinations live in the newly allocated Vec, rather than
        // inside the enclosing original's already-priced inline header.
        let headers = std::mem::size_of::<RootAuthorityNamesOriginalV1>()
            .checked_mul(3)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(overflow)?;
        let native =
            RootAuthorityNamesOriginalV1::fixed_demand_v1(RootAuthorityNameRecipeV1::Owner)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, headers)
                    .with(D::MetadataEntries, crate::native::RootPolicyNameObservationOriginalV1::retained_control_cells_v1()))
                .map_err(|_| overflow())?;
        let mut demand = aos_sandbox_ledger_replay::geometry::complete_replay_demand_v1(
            journal.read_view().state(),
            None,
        )?;
        for _ in 0..count {
            demand = demand.checked_add(native).map_err(|_| overflow())?;
        }
        // Each Vec child is priced above with its actual constructor/return
        // planes. Add only this parent and the allocation controls here.
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<std::alloc::Layout>().checked_mul(2)?)
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(overflow)?;
        demand
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(|_| overflow().into())
    }

    pub(super) fn observe_once(
        &mut self,
        journal: &RootPolicyJournalV1,
        pins: &RootAuthorityPinsOriginalV1,
    ) -> Result<(), ()> {
        if self.entered {
            self.reentered = true;
            return Err(());
        }
        self.entered = true;
        self.geometry = Some(Self::demand_v1(journal));
        let Some(Ok(demand)) = self.geometry else {
            return Err(());
        };
        self.admission = Some(journal.admit_role_observation_v1(demand));
        if !matches!(self.admission, Some(Ok(()))) {
            return Err(());
        }

        // Count actual raw members before any decoder or backing construction.
        // Invalid extra intents retain their original semantic refusal point;
        // no maximum is raised to make that family pass.
        let count = journal
            .records(RecordNamespace::DesiredState)
            .filter(|(key, _)| key.starts_with(INTENT_PREFIX))
            .count();
        self.allocation = Some(self.native.try_reserve_exact(count));
        if !matches!(self.allocation, Some(Ok(()))) {
            return Err(());
        }
        for _ in 0..count {
            self.native.push(RootAuthorityNamesOriginalV1::new());
        }
        self.outcome = Some(validate_history_with_pins_v1(
            journal,
            pins,
            &mut self.native,
        ));
        if matches!(self.outcome, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    pub(super) fn is_complete(&self) -> bool {
        self.entered && !self.reentered && matches!(self.outcome, Some(Ok(())))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.geometry
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|error| error as _)
            .or_else(|| {
                self.admission
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.allocation
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
            .or_else(|| {
                self.native
                    .iter()
                    .find_map(RootAuthorityNamesOriginalV1::failure)
            })
            .or_else(|| {
                self.outcome
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
    }
}

fn validate_history_with_pins_v1(
    journal: &RootPolicyJournalV1,
    pins: &RootAuthorityPinsOriginalV1,
    native: &mut [RootAuthorityNamesOriginalV1],
) -> Result<(), RootAuthorityErrorV1> {
    let namespace = RecordNamespace::DesiredState;
    let expected_pins = pins.record_bytes()?;
    let instance = journal
        .get(namespace, INSTANCE_KEY)
        .map(decode_instance)
        .transpose()?;
    let retained_pins = journal.get(namespace, PINS_KEY);
    if instance.is_some() != retained_pins.is_some()
        || retained_pins.is_some_and(|bytes| bytes != expected_pins)
    {
        return Err(RootAuthorityErrorV1::Stale);
    }
    let mut intents = 0_usize;
    let mut floors = 0_usize;
    let mut capacities = legacy_capacity_ids_for_purpose(
        journal.read_view().state(),
        GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor,
    )
    .map_err(Mechanical::from)?;
    for (key, value) in journal.records(namespace) {
        if key.starts_with(INTENT_PREFIX) {
            let intent = RootSourceGenesisIntentRecordV1::from_record_bytes(value)?;
            if instance != Some(intent.instance())
                || key != project_key(INTENT_PREFIX, intent.project())
                || intent.roles() != pins.digest()?
                || journal
                    .get(namespace, &project_key(FLOOR_PREFIX, intent.project()))
                    .is_some()
            {
                return Err(RootAuthorityErrorV1::Stale);
            }
            pins.verify_administrative_input(intent.accepted_input())?;

            // This is the original per-intent native gap, before recovering its
            // reservation or removing its identity from the complete family.
            let observation = native.get_mut(intents).ok_or(RootAuthorityErrorV1::Stale)?;
            observation
                .observe_once(journal, RootAuthorityNameRecipeV1::Owner)
                .map_err(|_| RootAuthorityErrorV1::Stale)?;
            // The old per-intent owner check disposed its positive temporary
            // probes before capacity decoding. Failed probes remain resident.
            observation.settle_positive_once_v1();
            let request = capacity::request(&intent);
            let admission = capacity::admission_id(&intent);
            let identity = reservation_id(&request, admission);
            let retained =
                lookup_capacity_record_v1(journal.read_view().historical_view(), identity)
                    .map_err(Mechanical::from)?
                    .ok_or(Mechanical::ProtectedBoundary)?;
            if retained.request.purpose
                != GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor
            {
                return Err(Mechanical::ForeignAuthorityNamespace.into());
            }
            let retained = retained.compare_provenance().map_err(Mechanical::from)?;
            if retained.request != request || retained.admission_transaction_id != admission {
                return Err(Mechanical::AuthorityPreflightMismatch.into());
            }
            let position = capacities
                .iter()
                .position(|candidate| *candidate == identity)
                .ok_or(RootAuthorityErrorV1::Stale)?;
            capacities.remove(position);
            intents += 1;
        } else if key.starts_with(FLOOR_PREFIX) {
            let floor = SourceHierarchyFloorRecordV1::from_record_bytes(value)?;
            if instance != Some(floor.instance())
                || key != project_key(FLOOR_PREFIX, floor.project())
                || floor.roles() != pins.digest()?
            {
                return Err(RootAuthorityErrorV1::Stale);
            }
            floors += 1;
        }
        if intents > 1 || floors > MAXIMUM_PROJECTS {
            return Err(RootAuthorityErrorV1::NonCanonical);
        }
    }
    if !capacities.is_empty() {
        return Err(RootAuthorityErrorV1::Stale);
    }

    // Borrow the SAME complete immutable canonical map. There is no copied
    // reducer, filtered namespace view, second replay or final-map adopter.
    let state = journal.read_view().state();
    let mut first_project = None;
    let has_foreign_project = state.keys().any(|(_, key)| {
        let project = key
            .strip_prefix(root_successor::INTENT_PREFIX)
            .or_else(|| key.strip_prefix(root_successor::SUCCESSOR_FLOOR_PREFIX));
        match (first_project, project) {
            (None, Some(project)) => {
                first_project = Some(project);
                false
            }
            (Some(first), Some(project)) => first != project,
            _ => false,
        }
    });
    if has_foreign_project {
        root_successor::validate_project_successor_replay_v3(state)?;
    } else {
        root_successor::validate_root_first_source_successor_state_v2(state)?;
    }
    Ok(())
}
