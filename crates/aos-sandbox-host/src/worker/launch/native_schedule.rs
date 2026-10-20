//! Derives finite native inspection limits from the genuine Launch residual.
//!
//! This is passive geometry. It prices both complete inspection owners and
//! the minimum SDK roster before searching the source-bounded scan size. Native
//! phases remain subject to their actual same-Launch entry gate.

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use super::schedule::HostLaunchWorkerScheduleV2;
use super::super::systemd::{
    PayloadInspectionLimitsV2, PayloadInspectionQuiescenceOriginalV2, SupervisorProofOriginalV2,
    RuntimeProofOriginalV2, SandboxNativeOriginalV2,
};
use crate::{HostError, Result};

const INSPECTIONS: usize = 2;

#[derive(Clone, Copy)]
pub(super) struct HostLaunchNativeScheduleV2 {
    limits: PayloadInspectionLimitsV2,
    demand: ResourceVector,
}

impl HostLaunchNativeScheduleV2 {
    pub(super) fn derive(remaining: ResourceVector, guardian_path_bytes: usize) -> Result<Self> {
        let sdk = HostLaunchWorkerScheduleV2::minimum_demand(guardian_path_bytes)?;
        let minimum = Self::for_extent(1)?;
        if !planning_requirement(minimum.demand, sdk)?
            .is_within(remaining)
        {
            return Err(HostError::ResourceExhausted);
        }
        // Every scanned entry incurs a real namespace charge, so this same
        // residual bounds the largest useful search. Directory/process caps
        // stay the existing kernel scanner's compiled caps.
        let mut lower = 1;
        let mut upper = usize::try_from(remaining.get(D::MetadataEntries))
            .map_err(|_| HostError::ResourceExhausted)?;
        let mut selected = minimum;
        while lower <= upper {
            let middle = lower + (upper - lower) / 2;
            let candidate = match Self::for_extent(middle) {
                Ok(candidate) => candidate,
                Err(_) => {
                    upper = middle - 1;
                    continue;
                }
            };
            let complete = planning_requirement(candidate.demand, sdk)?;
            if complete.is_within(remaining) {
                selected = candidate;
                lower = middle.checked_add(1).ok_or(HostError::ResourceExhausted)?;
            } else {
                upper = middle - 1;
            }
        }
        Ok(selected)
    }

    pub(super) fn minimum_demand() -> Result<ResourceVector> {
        Ok(Self::for_extent(1)?.demand)
    }

    pub(super) fn limits(self) -> PayloadInspectionLimitsV2 {
        self.limits
    }

    pub(super) fn demand(self) -> ResourceVector {
        self.demand
    }

    fn for_extent(entries: usize) -> Result<Self> {
        let directories = entries.min(super::super::MAXIMUM_PAYLOAD_CGROUPS);
        let processes = entries.min(super::super::MAXIMUM_PAYLOAD_PROCESSES);
        let limits = PayloadInspectionLimitsV2::new(directories, directories, processes, entries)
            .ok_or(HostError::ResourceExhausted)?;
        let native = PayloadInspectionQuiescenceOriginalV2::receiving_obligations_v2(limits)
            .ok_or(HostError::ResourceExhausted)?;
        let supervisor = SupervisorProofOriginalV2::receiving_obligations_v2()
            .ok_or(HostError::ResourceExhausted)?;
        let snapshot = RuntimeProofOriginalV2::receiving_obligations_v2()
            .ok_or(HostError::ResourceExhausted)?;
        let sandbox = SandboxNativeOriginalV2::receiving_obligations_v2()
            .ok_or(HostError::ResourceExhausted)?;
        let shifted = super::super::shifted_payload_inspection::ShiftedPayloadOriginalV2::receiving_obligations_v2()
            .ok_or(HostError::ResourceExhausted)?;
        let memory = native.0.checked_add(supervisor.0)
            .and_then(|bytes| bytes.checked_add(snapshot.0))
            .and_then(|bytes| bytes.checked_add(sandbox.0))
            .and_then(|bytes| bytes.checked_add(shifted.0))
            .and_then(|bytes| bytes.checked_mul(INSPECTIONS))
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<std::sync::Arc<tokio::sync::Mutex<PayloadInspectionQuiescenceOriginalV2>>>()
                    .checked_mul(INSPECTIONS)?.checked_mul(2)?,
            ))
            .and_then(|bytes| bytes.checked_add(
                (std::mem::size_of::<tokio::sync::Mutex<PayloadInspectionQuiescenceOriginalV2>>()
                    .checked_add(4 * std::mem::size_of::<usize>())?)
                    .checked_mul(INSPECTIONS)?,
            ))
            .and_then(|bytes| bytes.checked_add(
                (std::mem::size_of::<tokio::sync::Mutex<SupervisorProofOriginalV2>>()
                    .checked_add(4 * std::mem::size_of::<usize>())?)
                    .checked_mul(INSPECTIONS)?,
            ))
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<std::sync::Arc<tokio::sync::Mutex<SupervisorProofOriginalV2>>>()
                    .checked_mul(INSPECTIONS)?.checked_mul(2)?,
            ))
            .ok_or(HostError::ResourceExhausted)?;
        let memory = memory.checked_add(
            (std::mem::size_of::<tokio::sync::Mutex<RuntimeProofOriginalV2>>()
                .checked_add(4 * std::mem::size_of::<usize>()).ok_or(HostError::ResourceExhausted)?)
                .checked_mul(INSPECTIONS).ok_or(HostError::ResourceExhausted)?,
        ).and_then(|bytes| bytes.checked_add(
            std::mem::size_of::<std::sync::Arc<tokio::sync::Mutex<RuntimeProofOriginalV2>>>()
                .checked_mul(INSPECTIONS)?.checked_mul(2)?,
        )).ok_or(HostError::ResourceExhausted)?;
        let memory = memory.checked_add(
            (std::mem::size_of::<tokio::sync::Mutex<super::super::shifted_payload_inspection::ShiftedPayloadOriginalV2>>()
                .checked_add(4 * std::mem::size_of::<usize>()).ok_or(HostError::ResourceExhausted)?)
                .checked_mul(INSPECTIONS).ok_or(HostError::ResourceExhausted)?,
        ).and_then(|bytes| bytes.checked_add(
            std::mem::size_of::<std::sync::Arc<tokio::sync::Mutex<super::super::shifted_payload_inspection::ShiftedPayloadOriginalV2>>>()
                .checked_mul(INSPECTIONS)?.checked_mul(2)?,
        )).ok_or(HostError::ResourceExhausted)?;
        // The second proof point retains the first point's actual payload
        // pins. Completed sandbox prefixes retain only their returned leader
        // pins. During the kernel bookends, the current Q/supervisor/snapshot
        // and shifted prefixes still coexist until the full conjunction.
        let payload_pins = 1_usize + 1 + 1 + 4;
        let leader_pins = 1_usize;
        let kernel = super::super::kernel_recheck::PayloadKernelRechecksV2::receiving_obligations_v2()
            .ok_or(HostError::ResourceExhausted)?;
        let inspection_files = native.1.checked_add(payload_pins)
            .and_then(|files| files.checked_add(supervisor.1))
            .and_then(|files| files.checked_add(snapshot.1))
            .and_then(|files| files.checked_add(leader_pins.checked_mul(INSPECTIONS)?))
            .and_then(|files| files.checked_add(shifted.1))
            .and_then(|files| files.checked_add(kernel.1))
            .ok_or(HostError::ResourceExhausted)?;

        // A Ready-limit interval begins only after those temporary inspection
        // prefixes close. Both points' real payload/supervisor pins remain,
        // and the later exact read-only SDK observation may coexist with the
        // current limit owner. This is a planning ceiling, never admission.
        let limit_demand = super::super::limit_original::HostLimitNativeOriginalV2::receiving_demand_v2()
            .ok_or(HostError::ResourceExhausted)?;
        let sdk = minimum_readonly_files_v4()?;
        let ready_files = payload_pins.checked_add(leader_pins)
            .and_then(|files| files.checked_mul(INSPECTIONS))
            .and_then(|files| files.checked_add(usize::try_from(limit_demand.get(D::OpenFiles)).ok()?))
            .and_then(|files| files.checked_add(sdk))
            .ok_or(HostError::ResourceExhausted)?;
        let files = inspection_files.max(ready_files);
        let names = native.2.checked_add(supervisor.2)
            .and_then(|names| names.checked_add(snapshot.2))
            .and_then(|names| names.checked_add(sandbox.2))
            .and_then(|names| names.checked_add(shifted.2))
            .and_then(|names| names.checked_mul(INSPECTIONS)).ok_or(HostError::ResourceExhausted)?;
        let demand = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| HostError::ResourceExhausted)?)
            .with(D::OpenFiles, u64::try_from(files).map_err(|_| HostError::ResourceExhausted)?)
            .with(D::MetadataEntries, u64::try_from(names).map_err(|_| HostError::ResourceExhausted)?);
        Ok(Self { limits, demand })
    }
}

// Future native phases do not coexist merely because all their semantic
// reservoirs are reserved together. The actual entry gate uses the exact
// resident roster plus each next phase; this planning view is no grant.
fn planning_requirement(native: ResourceVector, sdk: ResourceVector) -> Result<ResourceVector> {
    let mut complete = native.checked_add(sdk).map_err(|_| HostError::ResourceExhausted)?;
    complete = complete.with(D::OpenFiles, native.get(D::OpenFiles).max(sdk.get(D::OpenFiles)));
    Ok(complete)
}

// Exact observation has no property-bearing request. Descriptor count is
// independent of the admitted reply extent; the minimum native schedule names
// the same complete receive/constructor/cleanup roster as the real call.
fn minimum_readonly_files_v4() -> Result<usize> {
    use aos_systemd::{HostSystemdCallV2, HostSystemdConnectionOriginalV2};

    let fixed = HostSystemdCallV2::fixed_request_wire_bytes_v2()
        .ok_or(HostError::ResourceExhausted)?;
    let schedule = HostSystemdCallV2::ExactObserve.receiving_schedule_with_request_bounds_v2(
        16, 0, fixed, 16, 0,
    ).map_err(|_| HostError::ResourceExhausted)?;
    let sdk = HostSystemdConnectionOriginalV2::receiving_footprint_v2(schedule)
        .ok_or(HostError::ResourceExhausted)?;
    let absence = super::ExactCgroupAbsenceOriginalV2::receiving_demand_v2()
        .ok_or(HostError::ResourceExhausted)?;
    sdk.open_files.checked_add(
        usize::try_from(absence.get(D::OpenFiles)).map_err(|_| HostError::ResourceExhausted)?,
    ).ok_or(HostError::ResourceExhausted)
}
