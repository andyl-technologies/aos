//! Reconstructs complete historical Cache families under the same private F.
//!
//! The existing canonical model supplier is debited before any evidence,
//! projection or recovery allocation. Every physical view has already passed
//! its own native/F bracket. This owner grants neither a Native capability nor
//! a signing purpose; the enclosing original retains all final bookends.

use super::CachePurposeReceivingV1;
use std::error::Error;
use aos_sandbox_model::{AccountingError, RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::{
    cache_state::{
        NodeCacheQuotaV1, clock_floor::CacheClockFloorDataV1,
        fixed_journals::CacheJournalRecipeRoleV1 as Role,
        recovery::RecoveryError,
        hold_state::CachePolicyHoldReadbackDataV1,
    },
    domain_ledger::create_storage_history::{
        KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
        cache_held::{CacheHeldBodyDataV1, CacheHeldReceiptDataV1},
        root_open::ROOT_HELLO_FRAME_BYTES_V1,
    },
};
use super::current_journals::CacheCurrentJournalsOriginalV1;
use super::{CacheSignerReceivingClosedV1 as Closed, Common, StageOriginals,
    admit_stage, cause, observe_original, sample_pair_demand};
use super::{challenge::CacheCurrentChallengeDataV1, request::CacheCurrentRequestOriginalV1};
use aos_sandbox_ledger_replay::cache_current::{CacheCurrentModelErrorV1, CacheCurrentInventoryDataV1};
type State = std::collections::BTreeMap<(aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>;

pub(super) struct CacheCurrentFamiliesDataV1 {
    inventory: CacheCurrentInventoryDataV1,
    clock: CacheClockFloorDataV1,
    hold: CachePolicyHoldReadbackDataV1,
    observed_held: CacheHeldBodyDataV1,
}

#[derive(Clone, Copy)]
enum First {
    Entry,
    Geometry,
    Funding,
    Before,
    Models,
    After,
    Deadline,
}

pub(super) struct CacheCurrentModelsOriginalV1 {
    stage: StageOriginals,
    geometry: Option<Result<ResourceVector, RecoveryError>>,
    models: Option<Result<CacheCurrentFamiliesDataV1, CacheCurrentModelErrorV1>>,
    clock: Option<rustix::time::Timespec>,
    deadline: Option<
        Result<
            rustix::time::Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    first: Option<First>,
}

impl CacheCurrentModelsOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            stage: Default::default(),
            geometry: None,
            models: None,
            clock: None,
            deadline: None,
            first: None,
        }
    }

    pub(super) fn observe_once(
        &mut self,
        common: &mut Common,
        journals: &CacheCurrentJournalsOriginalV1,
        sample: RawPairedClockSample,
        challenge: CacheCurrentChallengeDataV1,
        request: &CacheCurrentRequestOriginalV1,
        resident_files: u64,
        cutoff: u64,
    ) -> Result<(), Closed> {
        if self.geometry.is_some() || !journals.native_leaves_are_retired_v1() {
            return self.refuse(First::Entry);
        }
        self.geometry = Some(model_geometry(journals));
        let geometry = match self.geometry.as_ref() {
            Some(Ok(value)) => *value,
            _ => return self.refuse(First::Geometry),
        };
        self.stage.demand = Some((|| {
            let overflow = AccountingError::ArithmeticOverflow {
                dimension: D::MemoryBytes,
            };
            let inline = std::mem::size_of::<Self>()
                .checked_mul(2)
                .and_then(|bytes| {
                    bytes.checked_add(
                        std::mem::size_of::<CacheCurrentFamiliesDataV1>().checked_mul(2)?,
                    )
                })
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(overflow)?;
            geometry
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, inline))?
                .checked_add(sample_pair_demand()?)
        })());
        if admit_stage(common, &mut self.stage, resident_files).is_err() {
            return self.refuse(First::Funding);
        }
        self.stage.before_result = Some(observe_original(common, &mut self.stage.before));
        if !matches!(self.stage.before_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Before);
        }
        if self.first.is_none() {
            self.models = Some(reconstruct_families(journals, sample, challenge, request));
            if !matches!(self.models, Some(Ok(_))) {
                self.first.get_or_insert(First::Models);
            }
        }
        self.stage.after_result = Some(observe_original(common, &mut self.stage.after));
        if !matches!(self.stage.after_result, Some(Ok(()))) {
            self.first.get_or_insert(First::After);
        }
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        self.clock = Some(now);
        self.deadline =
            Some(aos_sandbox_broker::cache_signer_connection::deadline_timeout_v1(now, cutoff));
        if !matches!(self.deadline, Some(Ok(_))) {
            self.first.get_or_insert(First::Deadline);
        }
        if self.first.is_some() {
            return Err(Closed);
        }
        self.stage.retire_positive_samples()?;
        Ok(())
    }

    pub(super) fn data_v1(&self) -> Result<&CacheCurrentFamiliesDataV1, Closed> {
        if self.first.is_some() || !self.stage.native_retired {
            return Err(Closed);
        }
        self.models
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(Closed)
    }

    fn refuse(&mut self, first: First) -> Result<(), Closed> {
        self.first.get_or_insert(first);
        Err(Closed)
    }

    pub(super) fn failure<'a>(&'a self, common: &'a Common) -> Option<&'a (dyn Error + 'static)> {
        match self.first? {
            First::Entry => Some(&Closed),
            First::Geometry => cause(&self.geometry),
            First::Funding => self.stage.funding_failure(common),
            First::Before => self
                .stage
                .before
                .failure()
                .or_else(|| cause(&self.stage.before_result)),
            First::Models => cause(&self.models),
            First::After => self
                .stage
                .after
                .failure()
                .or_else(|| cause(&self.stage.after_result)),
            First::Deadline => cause(&self.deadline),
        }
    }
}

impl CacheCurrentFamiliesDataV1 {
    pub(super) fn observed_snapshot_v1(
        &self,
        journals: &CacheCurrentJournalsOriginalV1,
        objects: &super::current_objects::CacheCurrentObjectsOriginalV1,
        sample: RawPairedClockSample,
    ) -> Result<aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CacheHeldBodyDataV1, CacheCurrentModelErrorV1>{
        use CacheCurrentModelErrorV1::Changed;
        let now = u64::try_from(sample.wall_seconds())
            .map_err(|_| Changed)?
            .max(self.clock.observed_unix_seconds);
        self.inventory.require_live_at_v1(now)?;
        let (physical, manifest) = objects.completed_snapshot_v1().map_err(|_| Changed)?;
        let snapshot = aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CacheHeldBodyDataV1 {
            association: self.observed_held.association,
            source_held: self.observed_held.source_held,
            bootstrap: journals.coordinates_v1(Role::Bootstrap).ok_or(Changed)?,
            hold: journals.coordinates_v1(Role::Hold).ok_or(Changed)?,
            state: journals.coordinates_v1(Role::State).ok_or(Changed)?,
            authority: journals.coordinates_v1(Role::Authority).ok_or(Changed)?,
            clock: journals.coordinates_v1(Role::Clock).ok_or(Changed)?,
            physical,
            selected_partition: *self.inventory.selected_v1().partition.digest().as_bytes(),
            selected_head: *self.inventory.selected_v1().head.as_bytes(),
            quota: *self.inventory.quota_digest_v1().as_bytes(),
            disk_count: manifest.disk_count,
            negative_count: manifest.negative_count,
            pin_count: manifest.pin_count,
            clock_floor: self.clock.observed_unix_seconds,
        };
        let mut expected = self.observed_held;
        expected.hold = snapshot.hold;
        if snapshot != expected {
            return Err(Changed);
        }
        Ok(snapshot)
    }

    pub(super) fn quotas_v1(&self) -> &[NodeCacheQuotaV1] {
        self.inventory.quotas_v1()
    }
}

// The sole general recipe includes complete evidence and reconstruction. Its
// cardinality input counts every raw State row, including malformed members.
fn model_geometry(journals: &CacheCurrentJournalsOriginalV1) -> Result<ResourceVector, RecoveryError> {
    let views = journals.raw_views_v1().ok_or(RecoveryError::AnchorMismatch)?;
    aos_sandbox_ledger_replay::cache_current::model_geometry_v1(&views)
}

fn actual_state(
    journals: &CacheCurrentJournalsOriginalV1,
    role: Role,
) -> Result<&State, CacheCurrentModelErrorV1> {
    journals
        .state_v1(role)
        .ok_or(CacheCurrentModelErrorV1::Changed)
}

fn reconstruct_families(
    journals: &CacheCurrentJournalsOriginalV1,
    sample: RawPairedClockSample,
    challenge: CacheCurrentChallengeDataV1,
    request: &CacheCurrentRequestOriginalV1,
) -> Result<CacheCurrentFamiliesDataV1, CacheCurrentModelErrorV1> {
    use CacheCurrentModelErrorV1::Changed;
    use aos_sandbox_model::RecordNamespace;

    let views = journals.raw_views_v1().ok_or(Changed)?;
    let clock = aos_sandbox_ledger_replay::cache_current::decode_clock_v1(views.clock)?;
    if clock.observed_unix_seconds != challenge.expected_current.clock_floor {
        return Err(Changed);
    }
    let now = u64::try_from(sample.wall_seconds())
        .map_err(|_| Changed)?
        .max(clock.observed_unix_seconds);
    if now == 0 {
        return Err(Changed);
    }

    let raw_hold = actual_state(journals, Role::Hold)?;
    let hold = aos_sandbox_ledger_replay::cache_current::decode_hold_v1(views.hold)?;
    let held = hold.legacy.hold.ok_or(Changed)?;
    if !held.is_held()
        || hold.legacy.v8_pending.is_some()
        || hold
            .q04_pending
            .as_ref()
            .is_some_and(|pending| !pending.is_held())
        || held.project().as_bytes() != &challenge.expected_current.association.project
        || held.partition().as_bytes() != &challenge.expected_current.selected_partition
        || held.cache_head().as_bytes() != &challenge.expected_current.selected_head
    {
        return Err(Changed);
    }
    let raw_request = request.bytes().map_err(|_| Changed)?;
    let receipt = CacheHeldReceiptDataV1::decode(
        &raw_request[8 + ROOT_HELLO_FRAME_BYTES_V1..],
        challenge.root.open.lane,
    )?;
    let record_key = KeyV1::new(challenge.root.open.lane, OwnerV1::Cache, 1)?;
    let head_key = KeyV1::new(challenge.root.open.lane, OwnerV1::Cache, 0)?;
    let actual_record = raw_hold
        .get(&(
            RecordNamespace::CreateStorageHistory,
            record_key.encode().to_vec(),
        ))
        .ok_or(Changed)?;
    let actual_head = raw_hold
        .get(&(
            RecordNamespace::CreateStorageHistory,
            head_key.encode().to_vec(),
        ))
        .ok_or(Changed)?;
    if actual_record.as_slice() != receipt.record.as_slice()
        || actual_head.as_slice() != receipt.latest_head.as_slice()
    {
        return Err(Changed);
    }
    let actual_envelope =
        RecordEnvelopeV1::decode(actual_record, record_key, PhaseV1::new(OwnerV1::Cache, 1)?)?;
    let observed_held = CacheHeldBodyDataV1::decode(actual_envelope.body())?;

    let inventory = aos_sandbox_ledger_replay::cache_current::reconstruct_inventory_v1(
        &views, now, aos_sandbox_model::ProjectId::from_bytes(observed_held.association.project),
    )?;
    if inventory.selected_v1().partition.digest().as_bytes() != &observed_held.selected_partition
        || inventory.selected_v1().head.as_bytes() != &observed_held.selected_head
        || inventory.quota_digest_v1().as_bytes() != &observed_held.quota
    {
        return Err(Changed);
    }
    Ok(CacheCurrentFamiliesDataV1 { inventory, clock, hold, observed_held
    })
}

impl CachePurposeReceivingV1<'_> {
    pub(super) fn begin_current_models_once(&mut self) -> Result<(), Closed> {
        if self.original.first.is_some() || self.original.current_models.is_some() {
            return Err(self.fail(super::First::Closed));
        }
        let challenge = *self.original.root_challenge.data()?;
        let sample = self
            .original
            .current_clock
            .as_ref()
            .ok_or(Closed)?
            .before_sample_v1()?;
        let clock_files = self
            .original
            .current_clock_stage
            .demand
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(Closed)?
            .get(D::OpenFiles);
        let resident = self
            .current_purpose_resident_files_v1()?
            .checked_add(clock_files)
            .and_then(|files| files.checked_add(sample_pair_demand().ok()?.get(D::OpenFiles)))
            .ok_or(Closed)?;
        self.original.current_models = Some(CacheCurrentModelsOriginalV1::new());
        let result = self
            .original
            .current_models
            .as_mut()
            .ok_or(Closed)?
            .observe_once(
                &mut self.startup.common,
                self.original.current_journals.as_ref().ok_or(Closed)?,
                sample,
                challenge,
                self.original.root_request.as_ref().ok_or(Closed)?,
                resident,
                challenge.cutoff,
            );
        if result.is_err() {
            self.fail(super::First::CurrentModels);
        }
        result
    }
}
