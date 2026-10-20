//! Plans the actual finite launch SDK roster before catalog/export growth.
//!
//! This is passive checked representation DATA. Only the enclosing genuine
//! Launch borrower may admit it. Reply ceilings constrain the real retained
//! native decoder; they are not a promise that every possible reply will fit.

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_systemd::{
    GuardianUnitPropertyOriginalV2, HostLaunchReceiveScheduleV2, HostSystemdCallV2,
    HostSystemdConnectionOriginalV2, PayloadUnitPropertyOriginalV2,
};

use crate::{HostError, Result};

// Normal launch: 15 exact observations, one Guardian submission, one payload
// submission and two sandbox proofs. Compensation adds two entry observations,
// one possible failed-stop observation, and eight rounds each containing two
// observations, one stop and one possible failed-stop observation. A post-Unref
// observation uses one of the same 42 observation slots and has a smaller roster.
const EXACT_OBSERVATIONS: usize = 15 + 2 + 1 + 8 * (2 + 1);
const EXACT_STOPS: usize = 1 + 8;
pub(super) const RESIDENT_STOP_EFFECTS_V4: usize = 8;
const SANDBOX_OBSERVATIONS: usize = 2;
pub(super) const MAXIMUM_CALLS: usize = EXACT_OBSERVATIONS + EXACT_STOPS + SANDBOX_OBSERVATIONS + 2 + 1;

const MINIMUM_DBUS_MESSAGE_BYTES: usize = 16;

// Each actual effect row permits at most two native attempts, including all
// partial writes/readiness/Interrupted retries. There is no retry reset.
pub(super) const EFFECT_WRITE_ATTEMPTS_PER_CALL_V3: usize = 2;
pub(crate) const MAXIMUM_EFFECT_WRITE_ATTEMPTS_V3: usize =
    (EXACT_STOPS + 2) * EFFECT_WRITE_ATTEMPTS_PER_CALL_V3;

#[derive(Clone, Copy)]
pub(super) struct HostLaunchWorkerScheduleV2 {
    resident_stop: bool,
    guardian_request: usize,
    payload_request: usize,
    message_bytes: usize,
    demand: ResourceVector,
}

impl HostLaunchWorkerScheduleV2 {
    // All already-known property/native/constructor liabilities must be added
    // to the same Launch complete demand before its residual reaches this
    // function. The result is admitted whole before constructing any SDK owner
    // and before catalog/export observes its own remaining capacity.
    pub(super) fn derive(remaining: ResourceVector, guardian_path_bytes: usize) -> Result<Self> {
        let guardian_request = GuardianUnitPropertyOriginalV2::maximum_encoded_request_for_path_v2(
            guardian_path_bytes,
        ).ok_or(HostError::ResourceExhausted)?;
        let payload_request = PayloadUnitPropertyOriginalV2::maximum_encoded_request_bytes_v2()
            .ok_or(HostError::ResourceExhausted)?;

        Self::derive_program_v4(remaining, guardian_request, payload_request, false)
    }

    pub(super) fn derive_resident_stop_v4(remaining: ResourceVector) -> Result<Self> {
        // This closed program never emits an FD-bearing property request.
        // Its reply search still names the full fixed requested vocabulary.
        Self::derive_program_v4(remaining, 0, 0, true)
    }

    fn derive_program_v4(
        remaining: ResourceVector,
        guardian_request: usize,
        payload_request: usize,
        resident_stop: bool,
    ) -> Result<Self> {
        // A request source bound is a useful finite upper search target, not
        // an assertion about arbitrary manager replies. Every candidate is
        // checked against all dimensions of the SAME consumed Launch residual.
        let mut lower = MINIMUM_DBUS_MESSAGE_BYTES;
        let mut upper = guardian_request.max(payload_request).max(
            HostSystemdCallV2::fixed_request_wire_bytes_v2().ok_or(HostError::ResourceExhausted)?,
        ).max(lower);
        let minimum = Self::for_extent(guardian_request, payload_request, lower, resident_stop)?;
        if !minimum.demand.is_within(remaining) {
            return Err(HostError::ResourceExhausted);
        }
        let mut selected = minimum;
        while lower <= upper {
            let middle = lower + (upper - lower) / 2;
            let candidate = Self::for_extent(guardian_request, payload_request, middle, resident_stop)?;
            if candidate.demand.is_within(remaining) {
                selected = candidate;
                lower = middle.checked_add(1).ok_or(HostError::ResourceExhausted)?;
            } else {
                upper = middle - 1;
            }
        }
        Ok(selected)
    }

    pub(super) fn minimum_demand(guardian_path_bytes: usize) -> Result<ResourceVector> {
        let guardian = GuardianUnitPropertyOriginalV2::maximum_encoded_request_for_path_v2(guardian_path_bytes)
            .ok_or(HostError::ResourceExhausted)?;
        let payload = PayloadUnitPropertyOriginalV2::maximum_encoded_request_bytes_v2()
            .ok_or(HostError::ResourceExhausted)?;
        Ok(Self::for_extent(guardian, payload, MINIMUM_DBUS_MESSAGE_BYTES, false)?.demand)
    }

    pub(super) fn minimum_resident_stop_demand_v4() -> Result<ResourceVector> {
        Ok(Self::for_extent(0, 0, MINIMUM_DBUS_MESSAGE_BYTES, true)?.demand)
    }

    pub(super) fn is_resident_stop_v4(self) -> bool {
        self.resident_stop
    }

    pub(super) fn call_limit_for_program_v4(self, call: HostSystemdCallV2) -> usize {
        if self.resident_stop {
            match call {
                // Preparing an absent target may observe two units. Each of
                // eight reducer rounds observes both and may reobserve one
                // failed Stop job. The same finite ordinary reducer owns it.
                HostSystemdCallV2::ExactObserve | HostSystemdCallV2::PostUnrefObserve => 2 + 8 * 3,
                HostSystemdCallV2::ExactStop => RESIDENT_STOP_EFFECTS_V4,
                HostSystemdCallV2::GuardianStart | HostSystemdCallV2::PayloadStart
                    | HostSystemdCallV2::SandboxObserve | HostSystemdCallV2::SupervisorPolicy => 0,
            }
        } else {
            Self::call_limit(call)
        }
    }

    pub(super) fn demand(self) -> ResourceVector {
        self.demand
    }

    pub(super) fn call_limit(call: HostSystemdCallV2) -> usize {
        match call {
            HostSystemdCallV2::GuardianStart | HostSystemdCallV2::PayloadStart => 1,
            HostSystemdCallV2::SandboxObserve => SANDBOX_OBSERVATIONS,
            HostSystemdCallV2::SupervisorPolicy => 1,
            HostSystemdCallV2::ExactStop => EXACT_STOPS,
            HostSystemdCallV2::ExactObserve | HostSystemdCallV2::PostUnrefObserve => EXACT_OBSERVATIONS,
        }
    }

    pub(super) fn call(self, call: HostSystemdCallV2) -> Result<HostLaunchReceiveScheduleV2> {
        if self.call_limit_for_program_v4(call) == 0 {
            return Err(HostError::Fence("worker program does not contain this SDK call"));
        }
        let property_request = match call {
            HostSystemdCallV2::GuardianStart => self.guardian_request,
            HostSystemdCallV2::PayloadStart => self.payload_request,
            _ => 0,
        };
        let fixed_request = HostSystemdCallV2::fixed_request_wire_bytes_v2()
            .ok_or(HostError::ResourceExhausted)?;
        // Zero additional unrelated signal noise preserves the SDK's complete
        // mandatory bus/job/terminal roster. Excess native traffic refuses.
        let base = call.receiving_schedule_with_request_bounds_v2(
            self.message_bytes, property_request, fixed_request, self.message_bytes, 0,
        )
            .map_err(|_| HostError::ResourceExhausted)?;
        let materialized = base.raw_data_v2().incoming_messages()
            .checked_mul(self.message_bytes).ok_or(HostError::ResourceExhausted)?;
        call.receiving_schedule_with_request_bounds_v2(
            self.message_bytes, property_request, fixed_request, materialized, 0,
        )
            .map_err(|_| HostError::ResourceExhausted)
    }

    fn for_extent(guardian_request: usize, payload_request: usize, message_bytes: usize,
        resident_stop: bool) -> Result<Self> {
        let gate_bytes = crate::broker::HostLaunchWriteClockV2::sdk_gate_receiving_bytes_v3()
            .and_then(|bytes| bytes.checked_mul(if resident_stop { RESIDENT_STOP_EFFECTS_V4 } else { EXACT_STOPS + 2 }))
            .ok_or(HostError::ResourceExhausted)?;
        let mut result = Self { resident_stop, guardian_request, payload_request, message_bytes,
            demand: ResourceVector::ZERO };
        let mut largest_primary_files = 0_usize;
        let mut readonly_files = 0_usize;
        let mut largest_live_bytes = 0_usize;
        let mut compacted_bytes = 0_usize;
        let mut retained_sandbox_bytes = 0_usize;
        for call in [
            HostSystemdCallV2::GuardianStart,
            HostSystemdCallV2::PayloadStart,
            HostSystemdCallV2::SandboxObserve,
            HostSystemdCallV2::ExactObserve,
            HostSystemdCallV2::ExactStop,
            HostSystemdCallV2::SupervisorPolicy,
        ] {
            let count = result.call_limit_for_program_v4(call);
            if count == 0 { continue; }
            let schedule = result.call(call)?;
            if matches!(call, HostSystemdCallV2::SupervisorPolicy | HostSystemdCallV2::SandboxObserve
                | HostSystemdCallV2::GuardianStart | HostSystemdCallV2::PayloadStart) {
                // Returned state/job Strings and cgroup DATA may outlive
                // SDK wire compaction on their two actual upper owners. Two
                // bounded materialized planes cover construction and retention.
                retained_sandbox_bytes = retained_sandbox_bytes.checked_add(
                    schedule.raw_data_v2().maximum_materialized_bytes()
                        .checked_mul(2).and_then(|bytes| bytes.checked_mul(count))
                        .ok_or(HostError::ResourceExhausted)?,
                ).ok_or(HostError::ResourceExhausted)?;
            }
            let native = HostSystemdConnectionOriginalV2::receiving_footprint_v2(schedule)
                .ok_or(HostError::ResourceExhausted)?;
            let compacted = HostSystemdConnectionOriginalV2::compacted_receiving_bytes_v2(schedule)
                .ok_or(HostError::ResourceExhausted)?;
            let live = native.memory_bytes.checked_sub(compacted)
                .ok_or(HostError::ResourceExhausted)?;
            largest_live_bytes = largest_live_bytes.max(live);
            compacted_bytes = compacted_bytes.checked_add(
                compacted.checked_mul(count).ok_or(HostError::ResourceExhausted)?,
            ).ok_or(HostError::ResourceExhausted)?;
            let row = ResourceVector::ZERO
                .with(D::MetadataEntries, as_u64(native.metadata_entries)?)
                .with(D::NetworkBytes, as_u64(native.network_bytes)?)
                .with(D::LogBytes, as_u64(native.maximum_log_bytes)?);
            for _ in 0..count {
                result.demand = result.demand.checked_add(row)
                    .map_err(|_| HostError::ResourceExhausted)?;
            }
            largest_primary_files = largest_primary_files.max(native.open_files);
            if !matches!(call, HostSystemdCallV2::GuardianStart | HostSystemdCallV2::PayloadStart) {
                readonly_files = readonly_files.max(native.open_files);
            }
        }
        // Every completed call keeps its same-origin compact collector. At
        // most three unretired collectors may coexist; the real caller checks
        // the opaque physical-disposal AND storage-compaction proof before
        // opening another slot. A refused call therefore consumes its window
        // permanently. Namespace entries and spent traffic remain summed.
        let construction = std::mem::size_of::<super::HostLaunchWorkerOriginalV2>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<super::SystemdCallOriginalV2>()
                    .checked_mul(MAXIMUM_CALLS)?.checked_mul(2)?,
            ))
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<std::sync::Arc<tokio::sync::Mutex<super::SystemdCallOriginalV2>>>()
                    .checked_mul(MAXIMUM_CALLS)?.checked_mul(2)?,
            ))
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<tokio::sync::Mutex<super::SystemdCallOriginalV2>>()
                    .checked_add(2 * std::mem::size_of::<usize>())?
                    .checked_mul(MAXIMUM_CALLS)?,
            ))
            .ok_or(HostError::ResourceExhausted)?;
        let posts = std::mem::size_of::<super::ReadOnlyPostDestinationV2>()
            .checked_mul(2).and_then(|bytes| bytes.checked_mul(MAXIMUM_CALLS))
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or(HostError::ResourceExhausted)?;
        let memory = compacted_bytes.checked_add(largest_live_bytes.checked_mul(3)
            .ok_or(HostError::ResourceExhausted)?)
            .and_then(|bytes| bytes.checked_add(construction))
            .and_then(|bytes| bytes.checked_add(posts))
            .and_then(|bytes| bytes.checked_add(retained_sandbox_bytes))
            .and_then(|bytes| bytes.checked_add(gate_bytes))
            .and_then(|bytes| {
                let archive = if resident_stop { 0 } else {
                    aos_systemd::ServicePropertiesReadOriginalV2::receiving_memory_bytes_v2(12, 0)?
                };
                bytes.checked_add(archive)
            })
            .ok_or(HostError::ResourceExhausted)?;
        let files = largest_primary_files.checked_add(readonly_files.checked_mul(2)
            .ok_or(HostError::ResourceExhausted)?)
            .ok_or(HostError::ResourceExhausted)?;
        result.demand = result.demand
            .with(D::MemoryBytes, as_u64(memory)?)
            .with(D::OpenFiles, as_u64(files)?);
        // Actual completed Stop DTOs remain with every row through global
        // disposition; their dynamic paths/job strings are not compacted with
        // raw SDK buffers. Two full admitted materialized planes per Stop pay
        // these completed values separately from the raw collector's peak.
        let stop_dto = result.call(HostSystemdCallV2::ExactStop)?
            .raw_data_v2().maximum_materialized_bytes()
            .checked_mul(2).and_then(|bytes| bytes.checked_mul(result.call_limit_for_program_v4(HostSystemdCallV2::ExactStop))).ok_or(HostError::ResourceExhausted)?;
        result.demand = result.demand.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, as_u64(stop_dto)?))
            .map_err(|_| HostError::ResourceExhausted)?;
        let absence = super::ExactCgroupAbsenceOriginalV2::receiving_demand_v2()
            .ok_or(HostError::ResourceExhausted)?;
        let mut absence_roster = ResourceVector::ZERO;
        // A negative receiver remains live and therefore occupies one of the
        // same three native windows. Completed positive receivers physically
        // drop these exact root/path/probe leaves before window reuse. Names
        // remain the conservative sum over the fixed complete call roster.
        for dimension in [D::MemoryBytes, D::OpenFiles] {
            absence_roster = absence_roster.with(dimension,
                absence.get(dimension).checked_mul(3).ok_or(HostError::ResourceExhausted)?);
        }
        absence_roster = absence_roster.with(D::MetadataEntries,
            absence.get(D::MetadataEntries).checked_mul(MAXIMUM_CALLS as u64)
                .ok_or(HostError::ResourceExhausted)?);
        result.demand = result.demand.checked_add(absence_roster)
            .map_err(|_| HostError::ResourceExhausted)?;
        Ok(result)
    }
}

fn as_u64(value: usize) -> Result<u64> {
    u64::try_from(value).map_err(|_| HostError::ResourceExhausted)
}
