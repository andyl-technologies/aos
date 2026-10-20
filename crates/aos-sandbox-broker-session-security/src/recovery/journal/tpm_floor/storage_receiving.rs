//! Borrows only the two genuine Storage F financial sources at actual IO.
//!
//! This private sealed adapter has no native constructor or capability. Its
//! temporary borrow ends with the existing protected-floor operation. The real
//! writer, sidecar, physical process and native posts stay on their sole owners.

use aos_sandbox::{Journal, StorageFloorPhysicalProgramReceivingV2,
    StorageLifecycleSessionLoanV1, StoragePrepareReceivingLoanV1, StorageReceivingClosedV1};
use aos_sandbox_core::ResourceVector;

mod sealed {
    pub trait Sealed {}
    impl Sealed for aos_sandbox::StoragePrepareReceivingLoanV1<'_> {}
    impl Sealed for aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_> {}
}

pub(crate) trait StorageFloorFinancialSourceV2: sealed::Sealed {
    fn reserve_session_replay_v3(&mut self, main: &Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>;
    fn reserve_availability_v3(&mut self, main: &Journal, sidecar: &Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>;
    fn reserve_main_v3(&mut self, main: &Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>;
    fn reserve_sidecar_v2(&mut self, main: &Journal, sidecar: &Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>;
    fn begin_primitive_v2(&mut self, main: &Journal, sidecar: &Journal, complete: ResourceVector)
        -> Result<StorageFloorPhysicalProgramReceivingV2, StorageReceivingClosedV1>;
    fn finish_primitive_v2(&mut self, receipt: &StorageFloorPhysicalProgramReceivingV2,
        main: &Journal, sidecar: &Journal) -> Result<(), StorageReceivingClosedV1>;
}

impl StorageFloorFinancialSourceV2 for StoragePrepareReceivingLoanV1<'_> {
    fn reserve_session_replay_v3(&mut self, main: &Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    { self.reserve_session_replay_v3(main, complete) }

    fn reserve_availability_v3(&mut self, main: &Journal, sidecar: &Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    { self.reserve_floor_availability_v3(main, sidecar, complete) }

    fn reserve_main_v3(&mut self, main: &Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    { self.reserve_floor_main_v3(main, complete) }

    fn reserve_sidecar_v2(&mut self, main: &Journal, sidecar: &Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    { self.reserve_floor_sidecar_v2(main, sidecar, complete) }

    fn begin_primitive_v2(&mut self, main: &Journal, sidecar: &Journal, complete: ResourceVector)
        -> Result<StorageFloorPhysicalProgramReceivingV2, StorageReceivingClosedV1>
    { self.begin_floor_physical_program_v2(main, sidecar, complete) }

    fn finish_primitive_v2(&mut self, receipt: &StorageFloorPhysicalProgramReceivingV2,
        main: &Journal, sidecar: &Journal) -> Result<(), StorageReceivingClosedV1>
    { self.finish_floor_physical_program_v2(receipt, main, sidecar) }
}

impl StorageFloorFinancialSourceV2 for StorageLifecycleSessionLoanV1<'_, '_> {
    fn reserve_session_replay_v3(&mut self, main: &Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    { self.reserve_session_replay_v3(main, complete) }

    fn reserve_availability_v3(&mut self, main: &Journal, sidecar: &Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    { self.reserve_floor_availability_v3(main, sidecar, complete) }

    fn reserve_main_v3(&mut self, main: &Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    { self.reserve_floor_main_v3(main, complete) }

    fn reserve_sidecar_v2(&mut self, main: &Journal, sidecar: &Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    { self.reserve_floor_sidecar_v2(main, sidecar, complete) }

    fn begin_primitive_v2(&mut self, main: &Journal, sidecar: &Journal, complete: ResourceVector)
        -> Result<StorageFloorPhysicalProgramReceivingV2, StorageReceivingClosedV1>
    { self.begin_floor_physical_program_v2(main, sidecar, complete) }

    fn finish_primitive_v2(&mut self, receipt: &StorageFloorPhysicalProgramReceivingV2,
        main: &Journal, sidecar: &Journal) -> Result<(), StorageReceivingClosedV1>
    { self.finish_floor_physical_program_v2(receipt, main, sidecar) }
}
