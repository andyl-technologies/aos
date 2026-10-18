//! Creates a distinct fork target inside the Source's already-issued family.
//!
//! Source retains the single physical storage reservation. The fixed target
//! loan prepays separate local process and control custody and prevents Source
//! storage cleanup until every actual target process and alias has retired.

use super::*;
use crucible_linux_resource::LinuxProjectQuotaController;
use std::sync::Weak;

pub use original_roster::{QemuForkTargetConstructionError, QemuForkTargetConstructionLoan};

mod logical_reservation;
pub use logical_reservation::QemuForkTargetLogicalReservation;
mod ram_admission;
pub use ram_admission::QemuForkTargetRamAdmission;

/// Lends the one separately admitted target of an actual retained Source.
///
/// Only the genuine Source host can construct this move-only permit. It
/// carries no new resource allowance and must be consumed by that same host
/// factory. Dropping an unused permit releases no physical process or quota.
#[must_use = "consume once in the same Source host factory"]
pub struct LinuxQemuForkTargetPermit {
    reservation: Option<original_roster::ForkTargetReservation>,
    source: Weak<NativeResourceState>,
    quota: LinuxProjectQuotaController,
}

impl LinuxQemuForkTargetPermit {
    /// Copies this issued member's unchanged process geometry.
    ///
    /// These limits are requests, not another grant. The matching factory
    /// independently authenticates and consumes this actual move-only permit
    /// before it creates a Target cgroup or process owner.
    ///
    /// # Errors
    /// Refuses a permit whose actual reservation has already been consumed.
    pub fn resource_ceiling(&self) -> Result<(u32, u64, u64), QemuVmRealizationError> {
        self.reservation
            .as_ref()
            .map(|reservation| reservation.ceilings)
            .ok_or_else(|| missing_authority("observe actual Target process geometry"))
    }
}

/// Delivers exact cleanup custody even when logical Target landing refuses.
///
/// A refused landing exposes no launch permit. The same cleanup loan retains
/// that unconsumed permit internally until this exact role has returned.
#[must_use = "retain the actual Target outcome before reporting its refusal"]
pub enum QemuForkTargetPreparation {
    /// The genuine Source admitted this Target's unchanged landing.
    Ready {
        /// Move-only permit consumed by the same actual host factory.
        permit: LinuxQemuForkTargetPermit,
        /// Exact role cleanup access retained before any process birth.
        cleanup: QemuForkTargetConstructionLoan,
    },
    /// The actual occupied role remains retained after landing refusal.
    Retained {
        /// Same role and unconsumed permit, never an absence-based cleanup key.
        cleanup: QemuForkTargetConstructionLoan,
        /// Actual first admission/readback refusal and independent post.
        first: crucible_linux_resource::host_services::process_birth::NativePoolRefusal,
    },
}

#[derive(Debug)]
pub(super) struct ForkTargetCustody {
    pub(super) reservation: original_roster::ForkTargetReservation,
    source: Weak<NativeResourceState>,
    quota: LinuxProjectQuotaController,
}

impl LinuxQemuAttemptHostOwner {
    /// Reports whether this Source still owns a target loan or uncertain target.
    ///
    /// This gate precedes Source process or storage cleanup. Target owners
    /// themselves return false so their own physical retirement can proceed.
    #[must_use]
    pub fn fork_target_is_owned(&self) -> bool {
        self.fork_target.is_none()
            && self
                .original_account
                .as_ref()
                .is_some_and(NativeAccountAttempt::fork_target_is_owned)
    }

    /// Reserves the disjoint fixed target share before any target cgroup exists.
    ///
    /// Source's complete guest RAM and installed control floor remain charged.
    /// The future target must fit that same local floor and descriptor share;
    /// no second aggregate disk reservation is installed.
    ///
    /// # Errors
    /// Refuses terminal or nested targets, unavailable Source control, occupied
    /// target custody, stale original ownership, or insufficient local floors.
    pub fn prepare_fork_target(
        &mut self,
    ) -> Result<QemuForkTargetPreparation, QemuVmRealizationError> {
        self.check_operational_boundary()?;
        if self.fork_target.is_some() {
            return Err(missing_authority("lend nested QEMU fork target"));
        }
        let _controller = self.native_resource_controller()?;
        let state = self
            .native_resources
            .as_ref()
            .ok_or_else(|| missing_authority("retain QEMU fork Source control"))?;
        let quota = NativeResourceState::lend_quota(state).map_err(|source| {
            QemuVmRealizationError::ModelCopy {
                source: Box::new(source),
            }
        })?;
        let (reservation, mut cleanup, landing_refusal) = self
            .original_account
            .as_ref()
            .ok_or_else(|| missing_authority("retain QEMU fork Source account"))?
            .reserve_fork_target(self.process_contract()?)
            .map_err(original_roster::original_error)?;
        let permit = LinuxQemuForkTargetPermit {
            reservation: Some(reservation),
            source: Arc::downgrade(state),
            quota,
        };
        match landing_refusal {
            Some(first) => {
                cleanup.retain_failed_permit(permit);
                Ok(QemuForkTargetPreparation::Retained { cleanup, first })
            }
            None => Ok(QemuForkTargetPreparation::Ready { permit, cleanup }),
        }
    }

    /// Creates a fresh target directory beneath this Source's one actual quota.
    ///
    /// The target contract must name the separately retained target envelope in
    /// this same original family. Its assigned credentials remain Source's
    /// actual fork-inherited non-root credentials.
    ///
    /// # Errors
    /// Refuses absent Source storage, foreign or retired target contracts,
    /// invalid launch requirements, or quota and filesystem failures.
    pub fn prepare_fork_target_run_directory(
        &mut self,
        target_contract: &QemuChildProcessContract,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.check_operational_boundary()?;
        if self.fork_target.is_some() {
            return Err(missing_authority(
                "prepare nested QEMU fork target directory",
            ));
        }
        let original = self
            .original_account
            .as_ref()
            .ok_or_else(|| missing_authority("retain QEMU fork Source storage account"))?;
        original
            .verify_fork_target_contract(target_contract)
            .map_err(original_roster::original_error)?;
        let result = self
            .storage
            .as_mut()
            .ok_or_else(|| missing_authority("retain QEMU fork Source storage"))?
            .prepare_generation_run_directory(requirements, target_contract)
            .map_err(|source| map_storage_error("prepare QEMU fork target directory", &source));
        original.after(result)
    }

    /// Retains the separately issued Target purpose in its existing RAM keeper.
    ///
    /// This operation precedes socketpairs, spill files, workers and native
    /// descriptor staging. The Target keeps Source's immutable installer facts
    /// while its record names its own actual contained process and local share.
    ///
    /// # Errors
    /// Refuses ordinary Source owners, foreign custody or contracts, changed
    /// guest shape, stale originals, exhausted shares, or failed prefix encoding.
    /// An issued share stays retained on every later refusal.
    pub fn bind_fork_target_ram_custody(
        &mut self,
        contract: &QemuChildProcessContract,
        registration: &crate::ram_control::RamControlRegistration,
        supervisor: &crucible_linux_resource::host_supervision::HostOperationSupervisor,
        guest_ram_bytes: u64,
        custody: &crate::QemuRamLaunchCustody,
    ) -> Result<(), QemuVmRealizationError> {
        self.check_operational_boundary()?;
        if self.fork_target.is_none() || !custody.validates(registration) {
            return Err(missing_authority("retain QEMU fork target RAM purpose"));
        }
        self.process_contract()?
            .verify_process_stage_binding(&contract.retain_process_stage_binding())
            .map_err(|source| QemuVmRealizationError::ModelCopy {
                source: Box::new(source),
            })?;
        let binding = self
            .original_account
            .as_ref()
            .ok_or_else(|| missing_authority("retain QEMU fork target original"))?
            .prepare_fork_target_binding(contract, supervisor, registration, guest_ram_bytes)
            .map_err(|source| QemuVmRealizationError::ModelCopy {
                source: Box::new(source),
            })?;
        custody
            .cleanup
            .retain_target_binding(binding)
            .map_err(|source| QemuVmRealizationError::ModelCopy {
                source: Box::new(source),
            })?;
        let workspace = custody
            .cleanup
            .with_target_binding_mut(|binding| binding.prepare_fork_target_workspace())
            .map_err(|source| QemuVmRealizationError::ModelCopy {
                source: Box::new(source),
            })?
            .map_err(|source| QemuVmRealizationError::ModelCopy {
                source: Box::new(source),
            })?;
        custody
            .cleanup
            .retain_target_workspace(workspace)
            .map_err(|source| QemuVmRealizationError::ModelCopy {
                source: Box::new(source),
            })?;
        custody
            .cleanup
            .create_target_workspace()
            .map_err(|source| QemuVmRealizationError::ModelCopy {
                source: Box::new(source),
            })?;
        // The workspace host term and its physical keeper are populated before
        // freezing this Target's immutable allocation record.
        custody
            .cleanup
            .with_target_binding_mut(|binding| binding.seal_fork_target_prefix(contract))
            .map_err(|source| QemuVmRealizationError::ModelCopy {
                source: Box::new(source),
            })?
            .map_err(|source| QemuVmRealizationError::ModelCopy {
                source: Box::new(source),
            })?;
        self.original_account
            .as_ref()
            .ok_or_else(|| missing_authority("retain QEMU fork target prefix original"))?
            .require_original()
            .map_err(original_roster::original_error)
    }

    pub(super) fn fork_target_native_controller(
        &mut self,
    ) -> Result<LinuxQemuNativeResourceController, QemuVmRealizationError> {
        self.check_operational_boundary()?;
        let target = self
            .fork_target
            .as_ref()
            .ok_or_else(|| missing_authority("retain QEMU fork target custody"))?;
        if !target
            .source
            .upgrade()
            .is_some_and(|state| NativeResourceState::available(&state))
        {
            return Err(missing_authority(
                "retain QEMU fork Source physical control",
            ));
        }
        if self.native_resources.is_none() {
            let memory = self
                .process
                .as_ref()
                .ok_or_else(|| missing_authority("pin QEMU fork target memory"))?
                .memory_control()?;
            let state = NativeResourceState::new(
                memory,
                target.quota.clone(),
                self.maximum_resident_bytes,
                self.maximum_writable_bytes,
            );
            target
                .reservation
                .retain_control(OriginalNativeControlRetirement::retain(&state))
                .map_err(original_roster::original_error)?;
            self.native_resources = Some(state);
            self.original_retirement_pinned = true;
        }
        self.native_resources
            .as_ref()
            .map(NativeResourceState::controller)
            .ok_or_else(|| missing_authority("lend QEMU fork target control"))
    }

    pub(super) fn close_fork_target_physical_owners(
        &mut self,
    ) -> Result<(), QemuVmRealizationError> {
        let cleanup = self
            .fork_target
            .as_ref()
            .ok_or_else(|| missing_authority("retain QEMU fork target cleanup"))?
            .reservation
            .cleanup()
            .map_err(original_roster::original_error)?;
        self.retire_native_resources();
        if let Some(process) = self.process.as_mut() {
            process.finish_under_original(&cleanup)?;
        }
        self.process = None;
        if let Some(state) = self.native_resources.as_ref() {
            NativeResourceState::drain(state);
        }
        self.native_resources = None;
        self.fork_target
            .as_ref()
            .ok_or_else(|| missing_authority("retain QEMU fork target retirement"))?
            .reservation
            .mark_physical_closed()
            .map_err(original_roster::original_error)?;
        cleanup
            .wait_slice()
            .map(|_| ())
            .map_err(|source| original_roster::original_error(source.into()))
    }

    pub(super) fn finish_fork_target(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.terminal {
            return Err(missing_authority("finish uncertain QEMU fork target"));
        }
        self.close_fork_target_physical_owners()?;
        self.close_fork_target_vector()
    }

    pub(super) fn close_fork_target_vector(&mut self) -> Result<(), QemuVmRealizationError> {
        self.fork_target
            .as_mut()
            .ok_or_else(|| missing_authority("close QEMU fork target custody"))?
            .reservation
            .close()
            .map_err(original_roster::original_error)?;
        self.fork_target = None;
        self.original_account = None;
        self.terminal = true;
        Ok(())
    }

    pub(super) fn quarantine_fork_target(&mut self) {
        if let Some(target) = self.fork_target.as_ref() {
            target
                .reservation
                .retain_unsettled(original_roster::RetainedNativeHost {
                    process: self.process.take(),
                    storage: None,
                    native_resources: self.native_resources.take(),
                    unconfigured: None,
                });
        }
        self.terminal = true;
    }
}

impl LinuxQemuAttemptHostFactory {
    /// Joins this Main's permanent Target dispatcher after all jobs close.
    ///
    /// This is whole factory retirement, separate from individual campaign
    /// cleanup. Failure retains the same physical owners and entered Cleanup.
    ///
    /// # Errors
    /// Refuses live jobs, aliases, failed setup, expired saved Cleanup, or
    /// uncertain physical worker/window retirement or actual roster closure.
    pub fn finish_target_dispatcher(&mut self) -> Result<(), QemuVmRealizationError> {
        // Terminal intent blocks every later Source/Target birth, including
        // retries after an irreversible worker join or roster free.
        self.poisoned = true;
        self.verify_native_quiescent()?;
        let dispatcher = self.process.finish_target_dispatcher();
        if !self.process.target_dispatcher_physically_retired() {
            return crate::QemuTargetDispatcherRetirementError::combine(dispatcher, Ok(()));
        }
        drop(self.original_accounts.take());
        let pool = self
            .normal_pool
            .as_mut()
            .ok_or(OriginalActorAccountError::Unavailable)
            .and_then(|pool| pool.finish());
        // Return both actual leaf refusals. A historical dispatcher panic
        // neither skips pool return nor replaces its independent failure.
        crate::QemuTargetDispatcherRetirementError::combine(dispatcher, pool)
    }

    /// Observes the actual dispatcher, original accounts and node/World closure.
    ///
    /// This read-only fact grants no join, debit return, or new work authority.
    #[must_use]
    pub fn target_dispatcher_physically_retired(&self) -> bool {
        self.process.target_dispatcher_physically_retired()
            && self.original_accounts.is_none()
            && self
                .normal_pool
                .as_ref()
                .is_some_and(|pool| pool.is_physically_retired())
    }

    /// Borrows the existing panic payload until this containing factory drops.
    #[must_use]
    pub fn target_dispatcher_worker_panic(&mut self) -> Option<&(dyn std::any::Any + Send)> {
        self.process.target_dispatcher_worker_panic()
    }

    /// Borrows the first dispatcher Cleanup admission refusal, without entry.
    #[must_use]
    pub fn target_dispatcher_cleanup_admission_failure(
        &self,
    ) -> Option<&crucible_linux_resource::host_supervision::HostSupervisionError> {
        self.process.target_dispatcher_cleanup_admission_failure()
    }

    /// Creates the separately contained target of this factory's retained Source.
    ///
    /// The source reservation supplies both local shares and the one aggregate
    /// quota. The authored ceilings only restrict this existing assignment;
    /// they cannot create another bank or enlarge either local process limit.
    ///
    /// # Errors
    /// Refuses a foreign or stale permit, occupied or poisoned factory, altered
    /// credentials, insufficient authored ceilings, or failed cgroup creation
    /// and readback. Actual partial owners remain in the paid target slot.
    pub fn begin_fork_target(
        &mut self,
        mut permit: LinuxQemuForkTargetPermit,
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_writable_bytes: u64,
    ) -> Result<LinuxQemuAttemptHostOwner, QemuVmRealizationError> {
        let mut reservation = permit
            .reservation
            .take()
            .ok_or_else(|| missing_authority("consume QEMU fork target permit"))?;
        let binding = match self.normal_pool.as_ref() {
            Some(pool) => pool.binding_for_target(&reservation),
            None => self.original_accounts.as_ref(),
        }
        .ok_or_else(|| missing_authority("retain exact QEMU node fork-target factory"))?;
        reservation
            .verify_factory(binding)
            .map_err(original_roster::original_error)?;
        let ceilings = reservation.ceilings;
        if self.poisoned
            || self.process.is_poisoned()
            || maximum_vcpus != ceilings.0
            || maximum_resident_bytes < ceilings.1
            || maximum_writable_bytes != ceilings.2
            || !permit
                .source
                .upgrade()
                .is_some_and(|state| NativeResourceState::available(&state))
        {
            return Err(missing_authority(
                "admit QEMU fork target authored ceilings",
            ));
        }
        self.process
            .prepare_target_dispatcher(&reservation.attempt)?;
        reservation
            .begin_birth()
            .map_err(original_roster::original_error)?;
        let mut setup = crate::linux_attempt_process::OriginalProcessSetupCustody::default();
        let result = self.process.begin_fork_target_under_original(
            ceilings,
            reservation.descriptors,
            reservation.credentials,
            &reservation.attempt,
            &mut setup,
        );
        let process = match result {
            Ok(process) => process,
            Err(primary) => {
                self.poisoned = true;
                reservation.retain_unsettled(original_roster::RetainedNativeHost {
                    process: setup.owner,
                    storage: None,
                    native_resources: None,
                    unconfigured: setup.unconfigured,
                });
                return Err(reservation.attempt.after_refusal(primary));
            }
        };
        let mut host = LinuxQemuAttemptHostOwner {
            process: Some(process),
            storage: None,
            maximum_vcpus: ceilings.0,
            maximum_resident_bytes: ceilings.1,
            maximum_writable_bytes: ceilings.2,
            quarantine: None,
            native_resources: None,
            original_retirement_pinned: false,
            original_account: Some(reservation.borrow_attempt()),
            fork_target: Some(ForkTargetCustody {
                reservation,
                source: permit.source,
                quota: permit.quota,
            }),
            terminal: false,
        };
        let bound = host
            .fork_target
            .as_ref()
            .ok_or_else(|| missing_authority("retain QEMU fork target issued custody"))?
            .reservation
            .bind_contract(host.process_contract()?);
        if let Err(source) = bound {
            self.poisoned = true;
            let primary = original_roster::original_error(source);
            host.quarantine();
            return Err(primary);
        }
        Ok(host)
    }
}
