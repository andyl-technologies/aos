//! Checks the actual next native interval on the same consumed Launch.
//!
//! Every semantic/native receiver is already priced before construction. Native
//! descriptor phases are charged at their actual entry, including all still
//! resident negative prefixes. A primary submission also pays both bounded
//! read-only child intervals before IO; poison cannot manufacture a new loan.

use super::*;
use aos_sandbox_core::ResourceDimension as D;

use super::super::kernel_recheck::PayloadKernelRechecksV2;
use super::super::limit_original::HostLimitNativeOriginalV2;
use super::super::shifted_payload_inspection::ShiftedPayloadOriginalV2;
use super::super::systemd::{
    PayloadInspectionQuiescenceOriginalV2, RuntimeProofOriginalV2,
    SandboxNativeOriginalV2, StopQuiescenceOriginalV3, SupervisorProofOriginalV2,
};

pub(super) enum WorkerPhaseEntryV4 {
    Sdk(HostSystemdCallV2),
    Inspection,
    Supervisor,
    Snapshot,
    Shifted,
    Kernel,
    Limits,
    FinalPromotion,
}

impl HostLaunchWorkerReceivingV2<'_, '_> {
    pub(super) async fn admit_native_phase_v4(
        &mut self,
        entry: WorkerPhaseEntryV4,
    ) -> Result<HostLaunchWorkerPhaseV4> {
        let proposed = {
            let original = self.original.lock().await;
            if original.request != identity(self.request) || original.first.is_some() || original.compensation_entered {
                return Err(closed("native phase differs from its healthy actual Launch"));
            }
            original.phase_before_entry_v4(entry)
        };
        self.charge_native_phase_v4(proposed)
    }

    fn charge_native_phase_v4(
        &mut self,
        proposed: Result<HostLaunchWorkerPhaseV4>,
    ) -> Result<HostLaunchWorkerPhaseV4> {
        let result = proposed.and_then(|phase| {
            self.receiving.enter_launch_worker_phase_v4(&phase)?;
            Ok(phase)
        });

        match result {
            Ok(phase) => {
                if phase.compensation_prearm {
                    let mut original = self.original.try_lock()
                        .map_err(|_| closed("worker prearm original is borrowed"))?;
                    original.compensation_prearm = Some(phase);
                }
                Ok(phase)
            },
            Err(cause) => {
                let mut original = self.original.try_lock()
                    .map_err(|_| closed("actual worker phase refusal owner is borrowed"))?;
                original.phase_error.get_or_insert(cause);
                original.first.get_or_insert(WorkerFailureV2::Phase);
                Err(closed("actual worker phase refused; original cause remains resident"))
            }
        }
    }

    pub(super) fn admit_final_promotion_v4(&mut self) -> Result<()> {
        let proposed = {
            let original = self.original.try_lock()
                .map_err(|_| closed("actual final promotion roster is borrowed"))?;
            if original.request != identity(self.request)
                || original.first.is_some() || original.compensation_entered
                || original.completed_limit_points.len() != 2
                || original.active_limit_point
            {
                return Err(closed("final promotion lacks both actual disposed Ready points"));
            }
            original.phase_before_entry_v4(WorkerPhaseEntryV4::FinalPromotion)
        };
        self.charge_native_phase_v4(proposed).map(|_| ())
    }
}

impl HostLaunchWorkerOriginalV2 {
    fn phase_before_entry_v4(&self, entry: WorkerPhaseEntryV4) -> Result<HostLaunchWorkerPhaseV4> {
        if self.schedule.is_resident_stop_v4() && !matches!(entry, WorkerPhaseEntryV4::Sdk(_)) {
            return Err(closed("resident Stop cannot enter a Launch-only native program"));
        }
        let current = self.current_native_files_v4()?;
        let next = match entry {
            WorkerPhaseEntryV4::Sdk(call) => self.sdk_interval_files_v4(call)?,
            WorkerPhaseEntryV4::Inspection => self.inspection_files_v4()?,
            WorkerPhaseEntryV4::Supervisor => SupervisorProofOriginalV2::receiving_obligations_v2()
                .ok_or(HostError::ResourceExhausted)?.1,
            WorkerPhaseEntryV4::Snapshot => RuntimeProofOriginalV2::receiving_obligations_v2()
                .ok_or(HostError::ResourceExhausted)?.1,
            WorkerPhaseEntryV4::Shifted => ShiftedPayloadOriginalV2::receiving_obligations_v2()
                .ok_or(HostError::ResourceExhausted)?.1,
            WorkerPhaseEntryV4::Kernel => PayloadKernelRechecksV2::receiving_obligations_v2()
                .ok_or(HostError::ResourceExhausted)?.1,
            WorkerPhaseEntryV4::FinalPromotion => as_files(crate::broker::final_runtime_retention_demand_v4())?,
            WorkerPhaseEntryV4::Limits => {
                if self.active_limit_point {
                    return Err(closed("earlier limit native interval remains occupied"));
                }
                usize::try_from(HostLimitNativeOriginalV2::receiving_demand_v2()
                    .ok_or(HostError::ResourceExhausted)?.get(D::OpenFiles))
                    .map_err(|_| HostError::ResourceExhausted)?
            }
        };
        let compensation_prearm = !self.schedule.is_resident_stop_v4();
        let suffix = if compensation_prearm {
            self.sdk_interval_files_v4(HostSystemdCallV2::ExactObserve)?
                .max(self.sdk_interval_files_v4(HostSystemdCallV2::PostUnrefObserve)?)
                .max(self.sdk_interval_files_v4(HostSystemdCallV2::ExactStop)?)
                .checked_mul(LIVE_NATIVE_CALLS).ok_or(HostError::ResourceExhausted)?
        } else { 0 };
        Ok(HostLaunchWorkerPhaseV4 {
            request: self.request,
            current_native_files: current.checked_add(next).and_then(|files| files.checked_add(suffix))
                .ok_or(HostError::ResourceExhausted)?,
            compensation_prearm,
        })
    }

    fn inspection_files_v4(&self) -> Result<usize> {
        Ok(PayloadInspectionQuiescenceOriginalV2::receiving_obligations_v2(
            self.native_schedule.ok_or_else(|| closed("control program has no inspector"))?.limits(),
        ).ok_or(HostError::ResourceExhausted)?.1)
    }

    fn readonly_interval_files_v4(&self) -> Result<usize> {
        let sdk = HostSystemdConnectionOriginalV2::receiving_footprint_v2(
            self.schedule.call(HostSystemdCallV2::ExactObserve)?,
        ).ok_or(HostError::ResourceExhausted)?.open_files;
        sdk.checked_add(as_files(ExactCgroupAbsenceOriginalV2::receiving_demand_v2())?)
            .ok_or(HostError::ResourceExhausted)
    }

    pub(super) fn sdk_interval_files_v4(&self, call: HostSystemdCallV2) -> Result<usize> {
        let sdk = HostSystemdConnectionOriginalV2::receiving_footprint_v2(self.schedule.call(call)?)
            .ok_or(HostError::ResourceExhausted)?.open_files;
        let extra = match call {
            HostSystemdCallV2::GuardianStart => GuardianUnitPropertyOriginalV2::receiving_obligations_for_path_v2(
                self.guardian_path_bytes,
            ).ok_or(HostError::ResourceExhausted)?.1
                .checked_add(self.readonly_interval_files_v4()?.checked_mul(2)
                    .ok_or(HostError::ResourceExhausted)?)
                .ok_or(HostError::ResourceExhausted)?,
            HostSystemdCallV2::PayloadStart => PayloadUnitPropertyOriginalV2::receiving_obligations_v2()
                .ok_or(HostError::ResourceExhausted)?.1
                .checked_add(self.readonly_interval_files_v4()?.checked_mul(2)
                    .ok_or(HostError::ResourceExhausted)?)
                .ok_or(HostError::ResourceExhausted)?,
            HostSystemdCallV2::SandboxObserve => SandboxNativeOriginalV2::receiving_obligations_v2()
                .ok_or(HostError::ResourceExhausted)?.1
                .max(as_files(ExactCgroupAbsenceOriginalV2::receiving_demand_v2())?),
            HostSystemdCallV2::SupervisorPolicy => 0,
            HostSystemdCallV2::ExactStop => as_files(
                StopQuiescenceOriginalV3::receiving_demand_v3(),
            )?,
            HostSystemdCallV2::ExactObserve | HostSystemdCallV2::PostUnrefObserve => {
                as_files(ExactCgroupAbsenceOriginalV2::receiving_demand_v2())?
            }
        };
        sdk.checked_add(extra).ok_or(HostError::ResourceExhausted)
    }

    pub(super) fn current_native_files_v4(&self) -> Result<usize> {
        let mut files = 0_usize;
        for row in &self.calls {
            let row = row.try_lock().map_err(|_| closed("actual SDK native row is borrowed"))?;
            // A successful shutdown is insufficient. Only the exact physical
            // disposal or compaction proof removes the socket/message leaves.
            let native_disposed = row.disposal.as_ref().is_some_and(|result| {
                result.as_ref().is_ok_and(|proof| proof.belongs_to_v2(&row.native))
            }) || row.compaction.as_ref().is_some_and(|result| {
                result.as_ref().is_ok_and(|proof| proof.belongs_to_v2(&row.native))
            });
            if row.entered && !native_disposed {
                add(&mut files, HostSystemdConnectionOriginalV2::receiving_footprint_v2(
                    self.schedule.call(row.call)?,
                ).ok_or(HostError::ResourceExhausted)?.open_files)?;
            }
            if row.guardian.is_some() {
                add(&mut files, GuardianUnitPropertyOriginalV2::receiving_obligations_for_path_v2(
                    self.guardian_path_bytes,
                ).ok_or(HostError::ResourceExhausted)?.1)?;
            }
            if row.payload.is_some() {
                add(&mut files, PayloadUnitPropertyOriginalV2::receiving_obligations_v2()
                    .ok_or(HostError::ResourceExhausted)?.1)?;
            }
            if row.absence.is_some() {
                add(&mut files, as_files(ExactCgroupAbsenceOriginalV2::receiving_demand_v2())?)?;
            }
            if row.stop_native.is_some() {
                add(&mut files, as_files(StopQuiescenceOriginalV3::receiving_demand_v3())?)?;
            }
            if let Some(sandbox) = row.sandbox.as_ref() {
                let held = sandbox.native_files_after_completed_move_v4()
                    .unwrap_or(SandboxNativeOriginalV2::receiving_obligations_v2()
                        .ok_or(HostError::ResourceExhausted)?.1);
                add(&mut files, held)?;
            }
        }

        for original in &self.inspections {
            let disposed = original.try_lock().is_ok_and(|original| original.native_is_disposed_v4());
            // A completed Q moved seven actual payload pins to the readback;
            // they survive this collector's own temporary-file disposal.
            add(&mut files, if disposed { 1 + 1 + 1 + 4 } else { self.inspection_files_v4()? })?;
        }
        for original in &self.supervisors {
            if !original.try_lock().is_ok_and(|original| original.native_is_disposed_v4()) {
                add(&mut files, SupervisorProofOriginalV2::receiving_obligations_v2()
                    .ok_or(HostError::ResourceExhausted)?.1)?;
            }
        }
        for original in &self.snapshots {
            if !original.try_lock().is_ok_and(|original| original.native_is_disposed_v4()) {
                add(&mut files, RuntimeProofOriginalV2::receiving_obligations_v2()
                    .ok_or(HostError::ResourceExhausted)?.1)?;
            }
        }
        for (slot, original) in self.shifted.iter().enumerate() {
            // The kernel callback runs while this exact shifted owner is
            // borrowed. Charge its full prefix instead of relocking it or
            // treating a borrowed owner as positively disposed.
            let disposed = original.try_lock().is_ok_and(|original| {
                original.disposal_proof().is_some_and(|proof| proof.belongs_to_v2(&original, slot))
            });
            if !disposed {
                add(&mut files, ShiftedPayloadOriginalV2::receiving_obligations_v2()
                    .ok_or(HostError::ResourceExhausted)?.1)?;
            }
        }
        add(&mut files, self.kernel_rechecks.current_native_files_v4()
            .ok_or(HostError::ResourceExhausted)?)?;
        if self.active_limit_point {
            add(&mut files, as_files(HostLimitNativeOriginalV2::receiving_demand_v2())?)?;
        }
        Ok(files)
    }
}

fn as_files(vector: Option<aos_sandbox_core::ResourceVector>) -> Result<usize> {
    usize::try_from(vector.ok_or(HostError::ResourceExhausted)?.get(D::OpenFiles))
        .map_err(|_| HostError::ResourceExhausted)
}

fn add(total: &mut usize, files: usize) -> Result<()> {
    *total = total.checked_add(files).ok_or(HostError::ResourceExhausted)?;
    Ok(())
}
