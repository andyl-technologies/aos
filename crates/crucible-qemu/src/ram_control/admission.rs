//! Authenticates the actual pre-CPU inventory and grants retained resource subsets.
//!
//! One original setup guard covers report waiting, every bounded region exchange,
//! canonical topology construction and the grant. More records cannot extend it.

use super::*;
use crucible_ram::{Limits, RegionClass, RegionDescriptor, Topology};

/// Retains the original setup clock across host inventory admission and grant.
#[derive(Debug)]
pub(super) struct PendingAdmission {
    report: RamControlInventoryReport,
    guard: Option<HostOperationGuard>,
    deadline: Option<TransportDeadline>,
}

/// Authenticated immutable inventory received before native metadata allocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RamControlInventory {
    /// Native immutable topology generation and measured allocation requirements.
    pub report: RamControlInventoryReport,
    /// Canonical logical topology rebuilt from every authenticated region.
    pub topology: Topology,
}

impl RamControlClient {
    /// Receives and validates the entire actual native inventory under one guard.
    ///
    /// # Errors
    /// Returns a setup budget, transport, authority, geometry, identity, count,
    /// stale-generation or inconsistent-report error. Allocation follows bounded
    /// region-count validation, and no guest or QMP operation is required.
    pub fn inventory(&mut self) -> Result<RamControlInventory, RamControlError> {
        if self.pending_admission.is_some() {
            return Err(RamControlError::AuthorityMismatch);
        }
        let guard = self
            .supervisor
            .as_ref()
            .map(|supervisor| supervisor.begin_control(HostOperationClass::Setup))
            .transpose()
            .map_err(supervision_error)?;
        let deadline = self.exchange_deadline(guard.as_ref())?;
        let report = loop {
            let state = self.exchange_under(RamControlRequest::Status, guard.as_ref(), deadline)?;
            if let Some(report) = state.inventory {
                if state.logical_ram_bytes != report.logical_bytes || report.granted {
                    return Err(RamControlError::AuthorityMismatch);
                }
                break report;
            }
            if state.disposition != RamControlDisposition::Accepted
                && state.disposition != RamControlDisposition::Unavailable
            {
                return Err(RamControlError::AuthorityMismatch);
            }
            admission_wait(guard.as_ref(), deadline)?;
        };
        if report.region_count == 0 || report.region_count > 4096 {
            return Err(RamControlError::InvalidFrame);
        }
        let mut regions = Vec::new();
        regions
            .try_reserve_exact(report.region_count as usize)
            .map_err(|_| RamControlError::InvalidFrame)?;
        for ordinal in 0..report.region_count {
            let state = self.exchange_under(
                RamControlRequest::InventoryRegion {
                    topology_generation: report.topology_generation,
                    ordinal,
                },
                guard.as_ref(),
                deadline,
            )?;
            if state.disposition != RamControlDisposition::Accepted
                || state.inventory != Some(report)
                || state.logical_ram_bytes != report.logical_bytes
            {
                return Err(RamControlError::AuthorityMismatch);
            }
            let region = state
                .inventory_region
                .ok_or(RamControlError::InvalidFrame)?;
            if region.ordinal != ordinal {
                return Err(RamControlError::AuthorityMismatch);
            }
            let class = match region.class {
                1 => RegionClass::MutableMain,
                2 => RegionClass::MutableDevice,
                3 => RegionClass::ImmutableImage,
                4 => RegionClass::ContinuationPrivate,
                _ => return Err(RamControlError::InvalidFrame),
            };
            regions.push(
                RegionDescriptor::new(region.identity()?, class, region.logical_length)
                    .map_err(|_| RamControlError::InvalidFrame)?,
            );
        }
        let topology =
            Topology::new(regions, Limits::default()).map_err(|_| RamControlError::InvalidFrame)?;
        if topology.total_logical_bytes() != report.logical_bytes {
            return Err(RamControlError::AuthorityMismatch);
        }
        self.pending_admission = Some(PendingAdmission {
            report,
            guard,
            deadline,
        });
        Ok(RamControlInventory { report, topology })
    }

    /// Sends the exact host-admitted grant and waits for native admission completion.
    ///
    /// # Errors
    /// Returns stale topology, refused grant, transport, setup allowance or native
    /// failure. A receipt is returned only after native sealing and actual owner
    /// installation; accepting the grant request alone does not publish admission.
    pub fn grant_inventory(
        &mut self,
        inventory: &RamControlInventory,
        resources: HostResourceVector,
        spill_quota_bytes: u64,
    ) -> Result<(), RamControlError> {
        let pending = self
            .pending_admission
            .take()
            .ok_or(RamControlError::AuthorityMismatch)?;
        if pending.report != inventory.report {
            self.pending_admission = Some(pending);
            return Err(RamControlError::AuthorityMismatch);
        }
        let PendingAdmission {
            guard, deadline, ..
        } = pending;
        let mut state = self.exchange_under(
            RamControlRequest::GrantInventory {
                topology_generation: inventory.report.topology_generation,
                resources: resources_to_wire(resources),
                spill_quota_bytes,
            },
            guard.as_ref(),
            deadline,
        )?;
        loop {
            let report = state.inventory.ok_or(RamControlError::AuthorityMismatch)?;
            let mut expected = inventory.report;
            expected.granted = report.granted;
            if state.disposition != RamControlDisposition::Accepted || report != expected {
                return Err(RamControlError::AuthorityMismatch);
            }
            if report.granted {
                break;
            }
            admission_wait(guard.as_ref(), deadline)?;
            state = self.exchange_under(RamControlRequest::Status, guard.as_ref(), deadline)?;
        }
        if let Some(guard) = guard {
            guard.complete().map_err(supervision_error)?;
        }
        Ok(())
    }
}

fn admission_wait(
    guard: Option<&HostOperationGuard>,
    deadline: Option<TransportDeadline>,
) -> Result<(), RamControlError> {
    let duration = if let Some(guard) = guard {
        guard.wait_slice().map_err(supervision_error)?
    } else {
        deadline.ok_or(RamControlError::InvalidFrame)?.remaining()?
    };
    std::thread::sleep(duration.min(Duration::from_millis(10)));
    Ok(())
}

/// Converts retained host resource entitlements into the portable grant record.
pub fn resources_to_wire(resources: HostResourceVector) -> RamControlResources {
    RamControlResources {
        resident_peak_bytes: resources.resident_peak_bytes,
        backing_peak_bytes: resources.backing_peak_bytes,
        metadata_bytes: resources.metadata_bytes,
        staging_bytes: resources.staging_bytes,
        paging_io_slots: resources.paging_io_slots,
        cpu_slots: resources.cpu_slots,
        task_slots: resources.task_slots,
        file_descriptors: resources.file_descriptors,
    }
}
