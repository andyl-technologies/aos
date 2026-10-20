//! Joins prepaid helper and population observations to the actual Source anchor.
//!
//! All destinations are parked before native entry and remain with startup on
//! refusal. Membership and population are comparisons; they cannot fund helper
//! birth, authenticate its image or session, prove NV, or release any resource.

use aos_sandbox_linux::cgroup::{
    CgroupPopulationMonitor, CgroupPopulationMonitorOriginalV3, ExactCgroupMembershipReadbackV1,
};
use aos_sandbox_linux::pidfd::PidFd;

use super::*;

pub(super) struct ChildOriginal {
    observations: [ExactCgroupMembershipReadbackV1; 2],
    returned: [Option<Result<(), RuntimeBootPreparationReceivingClosedV1>>; 2],
    first: Option<usize>,
}

impl ChildOriginal {
    fn new() -> Self {
        Self {
            observations: std::array::from_fn(|_| ExactCgroupMembershipReadbackV1::new()),
            returned: [None; 2],
            first: None,
        }
    }

    fn demand() -> Option<ResourceVector> {
        let native = ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?
            .checked_sub(std::mem::size_of::<ExactCgroupMembershipReadbackV1>())?;
        let memory = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(native.checked_mul(2)?)?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(memory).ok()?)
                .with(
                    D::OpenFiles,
                    u64::try_from(
                        ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1
                            .checked_mul(2)?,
                    )
                    .ok()?,
                )
                .with(
                    D::MetadataEntries,
                    u64::try_from(ExactCgroupMembershipReadbackV1::receiving_metadata_cells_v1())
                        .ok()?,
                ),
        )
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let index = self.first?;
        self.observations[index]
            .failure()
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| result_failure(&self.returned[index]))
    }
}

pub(super) struct PopulationOriginal {
    capture: CgroupPopulationMonitorOriginalV3,
    returned: Option<Result<(), RuntimeBootPreparationReceivingClosedV1>>,
    taken: bool,
}

impl PopulationOriginal {
    fn new() -> Self {
        Self {
            capture: CgroupPopulationMonitorOriginalV3::new(),
            returned: None,
            taken: false,
        }
    }

    fn demand() -> Option<ResourceVector> {
        let (native, files, names) = CgroupPopulationMonitorOriginalV3::receiving_obligations_v3()?;
        let memory = native.checked_add(std::mem::size_of::<Self>().checked_mul(2)?)?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(memory).ok()?)
                .with(D::OpenFiles, u64::try_from(files).ok()?)
                .with(D::MetadataEntries, u64::try_from(names).ok()?),
        )
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.capture
            .failure()
            .or_else(|| result_failure(&self.returned))
    }
}

impl RuntimeBootPreparationStartupOriginalV1 {
    pub(in crate::runtime_deployment) fn require_child_v1(
        &self,
        child: &PidFd,
    ) -> Result<(), RuntimeBootPreparationStartupClosedV1> {
        self.require_current_v1()?;
        self.fund_additional(ChildOriginal::demand())?;
        let mut children = self
            .children
            .try_borrow_mut()
            .map_err(|_| self.fail(First::Order))?;
        let mut allocation = self
            .allocation
            .try_borrow_mut()
            .map_err(|_| self.fail(First::Order))?;
        *allocation = Some(children.try_reserve_exact(1));
        if !matches!(*allocation, Some(Ok(()))) {
            return Err(self.fail(First::Allocation));
        }
        drop(allocation);

        let index = children.len();
        children.push(ChildOriginal::new());
        let lane = children.last_mut().ok_or(self.closed)?;
        let mut source = self
            .source
            .try_borrow_mut()
            .map_err(|_| self.fail(First::Order))?;
        lane.returned[0] =
            Some(source.observe_helper_membership_once_v1(child, &mut lane.observations[0]));
        if !matches!(lane.returned[0], Some(Ok(()))) {
            lane.first.get_or_insert(0);
            self.fail(First::Child(index));
        }

        // This distinct post was funded before either native destination. It
        // must run even if the primary observation poisoned the Source owner.
        lane.returned[1] =
            Some(source.observe_helper_membership_owed_once_v1(child, &mut lane.observations[1]));
        if !matches!(lane.returned[1], Some(Ok(()))) {
            lane.first.get_or_insert(1);
            self.fail(First::Child(index));
        }
        if lane.first.is_some() {
            Err(self.closed)
        } else {
            Ok(())
        }
    }

    pub(in crate::runtime_deployment) fn retain_population_v1(
        &self,
    ) -> Result<CgroupPopulationMonitor, RuntimeBootPreparationStartupClosedV1> {
        self.require_current_v1()?;
        self.fund_additional(PopulationOriginal::demand())?;
        let mut populations = self
            .populations
            .try_borrow_mut()
            .map_err(|_| self.fail(First::Order))?;
        let mut allocation = self
            .allocation
            .try_borrow_mut()
            .map_err(|_| self.fail(First::Order))?;
        *allocation = Some(populations.try_reserve_exact(1));
        if !matches!(*allocation, Some(Ok(()))) {
            return Err(self.fail(First::Allocation));
        }
        drop(allocation);

        let index = populations.len();
        populations.push(PopulationOriginal::new());
        let lane = populations.last_mut().ok_or(self.closed)?;
        lane.returned = Some(
            self.source
                .try_borrow_mut()
                .map_err(|_| self.fail(First::Order))?
                .capture_population_once_v1(&mut lane.capture),
        );
        if !matches!(lane.returned, Some(Ok(()))) {
            return Err(self.fail(First::Population(index)));
        }
        let monitor = lane
            .capture
            .take_completed_once_v3()
            .ok_or_else(|| self.fail(First::Population(index)))?;
        lane.taken = true;
        Ok(monitor)
    }
}
