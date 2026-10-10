//! Issues one initial process subset from its preconfigured world family.
//!
//! The factory retains the family before issuing any process. A failed or
//! unwound admission leaves its slot occupied: absence of a returned record is
//! not physical cleanup. Staged CPU and I/O activation need the lower native
//! quiescence, drain and common-controller witnesses; none is inferred here.

use crucible_api::vm_lifecycle::{HostRamAdmissionError, HostRamProcessFamilyPartition};
use crucible_linux_resource::host_supervision::HostOperationSupervisor;
use crucible_linux_resource::ram_policy::{HostRamTarget, HostResourceVector};

#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
mod staged_assignment;
#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
pub(super) use staged_assignment::StageEarlyRefusal;
#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
pub(super) use staged_assignment::StageReborrowRefusal;
#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
pub(crate) use staged_assignment::{ConfiguredStageOperation, StagePrepareError};
#[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
use staged_assignment::{StageFailureCause, StagedProcessAssignment};

pub(super) struct ConfiguredProcessFamily {
    partition: HostRamProcessFamilyPartition,
    initial: Option<InitialProcessAssignment>,
    #[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
    staged: Option<StagedProcessAssignment>,
    original: HostOperationSupervisor,
}

// A fixed, non-Clone issuance record stays inside the SAME configured family.
// Its target is selected by the factory, never supplied as a scalar grant to
// a child or used to reconstruct an original resource owner.
struct InitialProcessAssignment {
    target: HostRamTarget,
    resources: HostResourceVector,
}

impl ConfiguredProcessFamily {
    pub(super) fn new(
        partition: HostRamProcessFamilyPartition,
        original: HostOperationSupervisor,
    ) -> Self {
        Self {
            partition,
            initial: None,
            #[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
            staged: None,
            original,
        }
    }

    pub(super) fn is_issued(&self) -> bool {
        self.initial.is_some()
    }

    pub(super) fn prepare_initial(
        &mut self,
        target: HostRamTarget,
    ) -> Result<HostResourceVector, HostRamAdmissionError> {
        self.original.verify_original_live()?;
        if target.owner_generation == 0
            || target.arena_generation == 0
            || target.owner_id == [0; 32]
            || target.node_id == [0; 32]
            || self.initial.is_some()
        {
            return Err(HostRamAdmissionError::contract(
                "process family initial assignment is stale or already issued",
            ));
        }
        let resources = self.partition.initial();
        self.initial = Some(InitialProcessAssignment { target, resources });
        // Publication is terminal by default. Refusal or unwind after this
        // point keeps the exact assigned process, including uncertain effects.
        self.original.verify_original_live()?;
        Ok(resources)
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(super) fn initial_target(&self) -> Option<HostRamTarget> {
        self.initial.as_ref().map(|initial| initial.target)
    }

    #[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
    pub(super) fn prepare_staged(
        &mut self,
        parent: HostRamTarget,
        arena_generation: u64,
        services: &crucible_linux_resource::host_services::HostServiceAllocator,
        contract: &crucible_qemu::QemuChildProcessContract,
    ) -> Result<ConfiguredStageOperation, StagePrepareError> {
        let prepare = || {
            self.original.verify_original_live()?;
            if self.staged.is_some() {
                return Err(StageEarlyRefusal::Invariant(
                    "configured process stage is occupied",
                ));
            }
            let initial = self.initial.as_ref().ok_or(StageEarlyRefusal::Invariant(
                "process stage has no issued initial owner",
            ))?;
            StagedProcessAssignment::prepare(
                self.partition,
                initial.target,
                parent,
                arena_generation,
                &self.original,
                services,
            )
        };
        let (record, operation) = prepare().map_err(|source| StagePrepareError::Before {
            source,
            original_after: self.original.verify_original_live().err(),
        })?;
        // Occupy before beginning Quiescence or duplicating the actual event.
        // Any failure or unwind after this point retains the real entered state.
        self.staged = Some(record);
        let entered = {
            let record = self.staged.as_mut().ok_or(StagePrepareError::Before {
                source: StageEarlyRefusal::Invariant("stage publication is unavailable"),
                original_after: self.original.verify_original_live().err(),
            })?;
            record.enter(contract)
        };
        // The occupied issuer and returned facade must agree before publication.
        // Verification refusal moves into the already-admitted entered body.
        let entered = entered.and_then(|()| {
            self.verify_staged(&operation)
                .map_err(StageFailureCause::Assignment)
        });
        let record = self.staged.as_ref().ok_or(StagePrepareError::Before {
            source: StageEarlyRefusal::Invariant("stage publication is unavailable"),
            original_after: self.original.verify_original_live().err(),
        })?;
        record.finish_entry(entered, operation)
    }

    #[cfg(any(test, all(target_os = "linux", feature = "private-measurement-domain")))]
    pub(super) fn verify_staged(
        &self,
        operation: &ConfiguredStageOperation,
    ) -> Result<(), StageEarlyRefusal> {
        self.original.verify_original_live()?;
        self.staged
            .as_ref()
            .ok_or(StageEarlyRefusal::Invariant(
                "process stage has no retained assignment",
            ))?
            .verify(operation)
    }

    pub(super) fn verify_initial(
        &self,
        target: HostRamTarget,
        resources: HostResourceVector,
    ) -> Result<(), HostRamAdmissionError> {
        self.original.verify_original_live()?;
        if self
            .initial
            .as_ref()
            .is_none_or(|assigned| assigned.target != target || assigned.resources != resources)
        {
            return Err(HostRamAdmissionError::contract(
                "process family assignment differs from its configured issuer",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
