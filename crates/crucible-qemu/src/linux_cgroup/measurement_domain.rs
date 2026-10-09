//! Static native-only cgroup delegation for disposable measurement hosts.
//!
//! This physical owner consumes an existing original controller loan. It does
//! not issue an operator entitlement or authenticate loader, storage or swap
//! birth. The enclosing private entry must retain those original purposes and
//! the genuine factory until both process and storage retirement complete.

use super::*;
use crucible_linux_resource::host_services::HostServiceLease;
use crucible_linux_resource::host_supervision::{
    HostOperationClass, HostOperationGuard, HostSupervisionError,
};

const MAX_NATIVE_CPUS: usize = 4;
const MAX_ACTOR_MEMORY: u64 = 16 << 30;
const CONTROLLERS: [&str; 4] = ["cpu", "memory", "pids", "cpuset"];

/// Fixed ordinary-resident ceilings for one disposable native domain.
///
/// The supplied CPU roster is an operator-selected physical subset, rather
/// than a measurement-derived choice. Storage and full birth admission remain
/// obligations of the enclosing original owner.
#[derive(Clone, Debug)]
pub struct MeasurementCgroupContract {
    limits: LinuxQemuCgroupLimits,
    cpus: [u32; MAX_NATIVE_CPUS],
    cpu_count: usize,
}

impl MeasurementCgroupContract {
    /// Validates a fixed one-, two- or four-CPU resident-only domain.
    ///
    /// # Errors
    /// Refuses another width, unordered or duplicate CPU IDs, invalid task or
    /// resident ceilings, and memory beyond the original sixteen-GiB actor.
    pub fn resident(
        cpus: &[u32],
        resident_bytes: u64,
        tasks: u32,
    ) -> Result<Self, MeasurementCgroupError> {
        if !matches!(cpus.len(), 1 | 2 | 4)
            || cpus.windows(2).any(|pair| pair[0] >= pair[1])
            || resident_bytes > MAX_ACTOR_MEMORY
        {
            return Err(MeasurementCgroupError::Contract);
        }
        let mut roster = [0; MAX_NATIVE_CPUS];
        roster[..cpus.len()].copy_from_slice(cpus);
        Ok(Self {
            limits: LinuxQemuCgroupLimits::new(cpus.len() as u32, resident_bytes, tasks)?,
            cpus: roster,
            cpu_count: cpus.len(),
        })
    }

    fn affinity(&self) -> String {
        self.cpus[..self.cpu_count]
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Refusal that leaves any published partial effect in its existing owner.
#[derive(Debug, Error)]
pub enum MeasurementCgroupError {
    /// The prospective fixed policy was invalid.
    #[error("invalid static native measurement policy")]
    Contract,
    /// The original controller loan or operation cannot cover this boundary.
    #[error("static native controller lacks its original loan or preparation scope")]
    Original,
    /// This owner was already installed or has not completed installation.
    #[error("static native controller is in the wrong lifecycle state")]
    State,
    /// The kernel did not preserve a required physical binding.
    #[error("static native controller binding differs at {control}")]
    Binding {
        /// Required control or identity.
        control: &'static str,
    },
    /// The existing concrete operation deadline or cancellation refused work.
    #[error("static native controller supervision refused: {0}")]
    Supervision(#[from] HostSupervisionError),
    /// An original cgroup operation failed.
    #[error("static native controller failed: {0}")]
    Cgroup(#[from] LinuxQemuCgroupError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DomainState {
    Fresh,
    Installing,
    Installed,
    Retired,
}

#[derive(Debug)]
enum PreparationCustody<'operation> {
    Borrowed(&'operation HostOperationGuard),
    Owned(HostOperationGuard),
    SharedOwned(Arc<HostOperationGuard>),
}

impl PreparationCustody<'_> {
    fn guard(&self) -> &HostOperationGuard {
        match self {
            Self::Borrowed(operation) => operation,
            Self::Owned(operation) => operation,
            Self::SharedOwned(operation) => operation,
        }
    }
}

/// Retains original credit and pinned partial effects until actual retirement.
///
/// No factory-root path is exported. The enclosing owner must construct and
/// retain the genuine factory internally. Failed installation can be retired
/// through this same record. Abandoning a created domain intentionally retains
/// its original loan and namespace lock for the process lifetime, preventing
/// premature refund; this is not a cleanup or joined-completion certificate.
#[derive(Debug)]
#[must_use = "created domains require explicit retirement before original credit closes"]
pub struct MeasurementCgroupOwner<'operation> {
    operation: Option<PreparationCustody<'operation>>,
    ancestor: Option<LinuxQemuCgroupRoot>,
    child: Option<LinuxQemuCgroupCleanupAuthority>,
    cleanup: Option<HostOperationGuard>,
    contract: MeasurementCgroupContract,
    state: DomainState,
    #[cfg(test)]
    drop_cut: Option<tests::DropCut<'operation>>,
    // Last: all physical pins and original cleanup controls close first.
    original: Option<HostServiceLease>,
}

/// Owns the same returned preparation for a retained, nonborrowing domain.
///
/// This owner retains the exact guard by value or through an admitted owning
/// alias. It creates no static reference, guard clone, clock or supervisor.
/// Complete original purpose and physical birth admission remain caller
/// obligations. This component cannot issue an authenticated operator grant.
#[derive(Debug)]
#[must_use = "created domains require explicit retirement before original credit closes"]
pub struct OwnedMeasurementCgroupOwner {
    inner: MeasurementCgroupOwner<'static>,
}

impl OwnedMeasurementCgroupOwner {
    /// Retains an admitted alias of the same returned original preparation.
    ///
    /// The used actor must precharge the guard's Arc body and control before
    /// constructing that Arc. External original paired credits must survive
    /// its last body/control free, including independent watchdog quarantine.
    /// This method creates no allocation, guard, clock, or supervisor.
    ///
    /// # Errors
    /// Refuses terminal or non-preparation scope and insufficient local loan
    /// bounds. Success is not complete purpose or physical birth admission.
    pub fn retain_shared_original(
        original: HostServiceLease,
        contract: MeasurementCgroupContract,
        operation: Arc<HostOperationGuard>,
    ) -> Result<Self, MeasurementCgroupError> {
        Ok(Self {
            inner: MeasurementCgroupOwner::retain_custody(
                original,
                contract,
                PreparationCustody::SharedOwned(operation),
            )?,
        })
    }

    /// Consumes the exact existing preparation and its original controller loan.
    ///
    /// Retained factories can move this owner without a self-reference. The
    /// same preparation identity and deadline govern installation and the
    /// existing same-supervisor Cleanup policy governs retirement. Abandoning
    /// installed effects retains the guard with their pins and original loan.
    ///
    /// # Errors
    /// Refuses a terminal or non-preparation guard and a controller loan below
    /// the same local descriptor and control-buffer lower bounds. Success does
    /// not certify complete Source, stack, factory or prebirth funding.
    pub fn retain_owned(
        original: HostServiceLease,
        contract: MeasurementCgroupContract,
        operation: HostOperationGuard,
    ) -> Result<Self, MeasurementCgroupError> {
        Ok(Self {
            inner: MeasurementCgroupOwner::retain_custody(
                original,
                contract,
                PreparationCustody::Owned(operation),
            )?,
        })
    }

    /// Installs the static domain using its retained original preparation.
    ///
    /// # Errors
    /// Refuses reuse, original supervision, incompatible or contested
    /// delegation, and kernel control or identity failures. Partial effects
    /// remain retained by this same owner.
    pub fn install(
        &mut self,
        ancestor_path: &Path,
        name: &str,
    ) -> Result<(), MeasurementCgroupError> {
        self.inner.install(ancestor_path, name)
    }

    /// Retires through the same supervisor's original finite Cleanup policy.
    ///
    /// # Errors
    /// Retains custody on supervision refusal, remaining processes or children,
    /// contested or changed identities, and failed physical removal.
    pub fn retire(&mut self) -> Result<(), MeasurementCgroupError> {
        self.inner.retire()
    }
}

impl<'operation> MeasurementCgroupOwner<'operation> {
    /// Retains the existing controller loan and borrows its original preparation scope.
    ///
    /// Setup cannot substitute a new preparation operation. Retirement starts
    /// only the existing cleanup policy in that same retained supervisor.
    ///
    /// The local descriptor and byte checks are lower bounds; they do not
    /// establish complete heap, stack, control or original birth cost.
    ///
    /// # Errors
    /// Refuses a non-preparation or terminal scope, or a loan smaller than the
    /// local control buffer and descriptor peak.
    pub fn retain_original(
        original: HostServiceLease,
        contract: MeasurementCgroupContract,
        operation: &'operation HostOperationGuard,
    ) -> Result<Self, MeasurementCgroupError> {
        Self::retain_custody(original, contract, PreparationCustody::Borrowed(operation))
    }

    fn retain_custody(
        original: HostServiceLease,
        contract: MeasurementCgroupContract,
        operation: PreparationCustody<'operation>,
    ) -> Result<Self, MeasurementCgroupError> {
        let guard = operation.guard();
        boundary(guard)?;
        if guard.status()?.class != HostOperationClass::Preparation {
            return Err(MeasurementCgroupError::Original);
        }
        if original.file_descriptors() < 6 || original.resident_bytes() < 4096 {
            return Err(MeasurementCgroupError::Original);
        }
        Ok(Self {
            operation: Some(operation),
            ancestor: None,
            child: None,
            cleanup: None,
            contract,
            state: DomainState::Fresh,
            #[cfg(test)]
            drop_cut: None,
            original: Some(original),
        })
    }

    /// Creates and delegates the fixed resident-only parent under an original guard.
    ///
    /// Every created inode is saved before the next fallible operation. Ordinary
    /// factory creation remains unchanged and continues to install leaf swap zero.
    ///
    /// # Errors
    /// Refuses reuse, cancelled or expired original supervision, nonempty or
    /// incompatible delegation, namespace contention, and any failed exact
    /// control or inode readback. The borrowed owner retains partial effects.
    pub fn install(
        &mut self,
        ancestor_path: &Path,
        name: &str,
    ) -> Result<(), MeasurementCgroupError> {
        let operation = self
            .operation
            .as_ref()
            .ok_or(MeasurementCgroupError::State)?
            .guard();
        if self.state != DomainState::Fresh {
            return Err(MeasurementCgroupError::State);
        }
        self.state = DomainState::Installing;
        boundary(operation)?;
        validate_cgroup_name(name)?;
        self.ancestor = Some(LinuxQemuCgroupRoot::acquire(ancestor_path)?);
        let ancestor = self
            .ancestor
            .as_ref()
            .ok_or(MeasurementCgroupError::State)?;
        check_text(&ancestor.directory, &ancestor.path, "cgroup.type", "domain")?;
        check_text(&ancestor.directory, &ancestor.path, "cgroup.procs", "")?;
        let available = read_words(
            &ancestor.directory,
            &ancestor.path,
            "cgroup.subtree_control",
        )?;
        for controller in CONTROLLERS {
            if !available.contains(controller) {
                return Err(LinuxQemuCgroupError::MissingController { controller }.into());
            }
        }
        boundary(operation)?;
        let path = ancestor.path.join(name);
        let parent_directory = duplicate_fd(
            ancestor.directory.as_raw_fd(),
            "retain static native ancestor",
            &path,
        )?;
        mkdirat(&ancestor.directory, name, Mode::from_bits_truncate(0o700)).map_err(|source| {
            LinuxQemuCgroupError::Io {
                operation: "create static native domain",
                path: path.clone(),
                source: source.into(),
            }
        })?;
        self.child = Some(LinuxQemuCgroupCleanupAuthority {
            path,
            parent_directory,
            name: name.to_owned(),
            directory: None,
            original_removed: false,
        });
        let child = self.child.as_mut().ok_or(MeasurementCgroupError::State)?;
        boundary(operation)?;
        child.pin_directory()?;
        let directory = child
            .directory
            .as_ref()
            .ok_or(MeasurementCgroupError::State)?;
        check_text(directory, &child.path, "cgroup.type", "domain")?;
        check_text(directory, &child.path, "cgroup.procs", "")?;
        let settings = [
            ("cpu.max", self.contract.limits.cpu_max()?),
            (
                "memory.max",
                self.contract.limits.maximum_resident_bytes.to_string(),
            ),
            ("memory.swap.max", String::from("0")),
            ("pids.max", self.contract.limits.maximum_tasks.to_string()),
        ];
        for (control, value) in settings {
            boundary(operation)?;
            write_control(directory, &child.path, control, value.as_bytes())?;
            boundary(operation)?;
        }
        boundary(operation)?;
        let mut affinity =
            open_control(directory, &child.path, "cpuset.cpus", ControlAccess::Write)?;
        affinity
            .write_all(self.contract.affinity().as_bytes())
            .map_err(|source| LinuxQemuCgroupError::Io {
                operation: "install static native affinity",
                path: child.path.clone(),
                source,
            })?;
        drop(affinity);
        boundary(operation)?;
        // The kernel canonicalizes adjacent CPU IDs into ranges. Compare the
        // checked finite roster, not its spelling, for both requested/effective.
        if cpu_roster(&read_text(directory, &child.path, "cpuset.cpus")?)?
            != self.contract.cpus[..self.contract.cpu_count]
        {
            return Err(MeasurementCgroupError::Binding {
                control: "cpuset.cpus",
            });
        }
        // subtree_control accepts command tokens but reads back controller
        // names, so it needs its own exact set check rather than write_control.
        let mut control = open_control(
            directory,
            &child.path,
            "cgroup.subtree_control",
            ControlAccess::Write,
        )?;
        boundary(operation)?;
        control
            .write_all(b"+cpu +memory +pids +cpuset")
            .map_err(|source| LinuxQemuCgroupError::Io {
                operation: "delegate static native controllers",
                path: child.path.clone(),
                source,
            })?;
        drop(control);
        boundary(operation)?;
        let delegated = read_words(directory, &child.path, "cgroup.subtree_control")?;
        if delegated != CONTROLLERS.into_iter().map(str::to_owned).collect() {
            return Err(MeasurementCgroupError::Binding {
                control: "cgroup.subtree_control",
            });
        }
        let effective = read_text(directory, &child.path, "cpuset.cpus.effective")?;
        if cpu_roster(&effective)? != self.contract.cpus[..self.contract.cpu_count] {
            return Err(MeasurementCgroupError::Binding {
                control: "cpuset.cpus.effective",
            });
        }
        boundary(operation)?;
        verify_directory_identity(&child.parent_directory, &child.name, directory, &child.path)?;
        boundary(operation)?;
        self.state = DomainState::Installed;
        Ok(())
    }

    /// Removes the same empty domain only after genuine factory locks close.
    ///
    /// The namespace flock rejects surviving cooperating factory owners. The
    /// kernel's descriptor-relative directory removal additionally refuses
    /// remaining child cgroups. Storage/project retirement is separately
    /// required by the enclosing original owner.
    ///
    /// Starts the existing original finite Cleanup policy once and publishes
    /// that guard before physical retirement. A terminal preparation cannot
    /// substitute a later preparation deadline.
    ///
    /// # Errors
    ///
    /// Retains custody on expired cleanup, namespace contention, inode
    /// replacement, remaining processes or children, and failed removal.
    pub fn retire(&mut self) -> Result<(), MeasurementCgroupError> {
        if self.state == DomainState::Retired {
            return Err(MeasurementCgroupError::State);
        }
        if self.cleanup.is_none() {
            self.cleanup = Some(
                self.operation
                    .as_ref()
                    .ok_or(MeasurementCgroupError::State)?
                    .guard()
                    .begin_original_cleanup_control()?,
            );
        }
        let operation = self.cleanup.as_ref().ok_or(MeasurementCgroupError::State)?;
        boundary(operation)?;
        let Some(child) = self.child.as_mut() else {
            self.ancestor = None;
            self.state = DomainState::Retired;
            return Ok(());
        };
        child.pin_directory()?;
        let directory = child
            .directory
            .as_ref()
            .ok_or(MeasurementCgroupError::State)?;
        verify_directory_identity(&child.parent_directory, &child.name, directory, &child.path)?;
        lock_namespace(directory, &child.path)?;
        boundary(operation)?;
        let mut events =
            open_control(directory, &child.path, "cgroup.events", ControlAccess::Read)?;
        if read_populated(&mut events, &child.path)? {
            return Err(MeasurementCgroupError::Binding {
                control: "populated",
            });
        }
        boundary(operation)?;
        unlinkat(
            &child.parent_directory,
            child.name.as_str(),
            AtFlags::REMOVEDIR,
        )
        .map_err(|source| LinuxQemuCgroupError::Io {
            operation: "retire static native domain",
            path: child.path.clone(),
            source: source.into(),
        })?;
        self.child = None;
        self.ancestor = None;
        self.state = DomainState::Retired;
        boundary(operation)?;
        Ok(())
    }
}

impl Drop for MeasurementCgroupOwner<'_> {
    fn drop(&mut self) {
        if self.child.is_some() {
            // Partial kernel effects cannot refund a live original purpose.
            // Explicit retirement is the only path that releases these pins.
            if let Some(child) = self.child.take() {
                std::mem::forget(child);
            }
            if let Some(ancestor) = self.ancestor.take() {
                std::mem::forget(ancestor);
            }
            if let Some(cleanup) = self.cleanup.take() {
                std::mem::forget(cleanup);
            }
            if let Some(operation) = self.operation.take() {
                std::mem::forget(operation);
            }
            if let Some(original) = self.original.take() {
                std::mem::forget(original);
            }
        } else {
            // Pre-mkdir refusal still owns an actual namespace descriptor.
            // Close it before the original credit can be refunded.
            drop(self.ancestor.take());
            #[cfg(test)]
            if let Some(cut) = self.drop_cut.as_mut() {
                cut.sample();
            }
        }
    }
}

fn boundary(operation: &HostOperationGuard) -> Result<(), MeasurementCgroupError> {
    operation.wait_slice()?;
    Ok(())
}

fn read_text(
    directory: &OwnedFd,
    path: &Path,
    control: &'static str,
) -> Result<String, MeasurementCgroupError> {
    let mut file = open_control(directory, path, control, ControlAccess::Read)?;
    Ok(read_control(
        &mut file,
        &path.join(control),
        "read static native control",
        MAX_CGROUP_CONTROL_BYTES,
    )?)
}

fn check_text(
    directory: &OwnedFd,
    path: &Path,
    control: &'static str,
    expected: &str,
) -> Result<(), MeasurementCgroupError> {
    if read_text(directory, path, control)?.trim_ascii_end() != expected {
        return Err(MeasurementCgroupError::Binding { control });
    }
    Ok(())
}

fn cpu_roster(value: &str) -> Result<Vec<u32>, MeasurementCgroupError> {
    let mut cpus = Vec::with_capacity(MAX_NATIVE_CPUS);
    for component in value.trim_ascii_end().split(',') {
        let (first, last) = component.split_once('-').unwrap_or((component, component));
        let first: u32 = first
            .parse()
            .map_err(|_| MeasurementCgroupError::Contract)?;
        let last: u32 = last.parse().map_err(|_| MeasurementCgroupError::Contract)?;
        if first > last || u64::from(last) - u64::from(first) >= MAX_NATIVE_CPUS as u64 {
            return Err(MeasurementCgroupError::Contract);
        }
        for cpu in first..=last {
            if cpus.len() == MAX_NATIVE_CPUS || cpus.last().is_some_and(|previous| *previous >= cpu)
            {
                return Err(MeasurementCgroupError::Contract);
            }
            cpus.push(cpu);
        }
    }
    Ok(cpus)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_original_retains_the_actual_guard_until_its_last_owner() {
        use crucible_linux_resource::host_services::HostServiceAllocator;
        use crucible_linux_resource::host_supervision::{
            HostOperationBudgets, HostOperationSupervisor,
        };

        let allocator = HostServiceAllocator::new(1, 6, 4096).unwrap();
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        // Mechanism-only Arc custody: this local fixture is not a complete
        // original Arc/control payment or installed retirement witness.
        let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
        let identity = original.status().unwrap().operation_id;
        let contract = MeasurementCgroupContract::resident(&[1], 1, 1).unwrap();
        let loan = allocator.reserve_resources(0, 6, 4096).unwrap();
        let owner = OwnedMeasurementCgroupOwner::retain_shared_original(
            loan,
            contract,
            Arc::clone(&original),
        )
        .unwrap();

        let PreparationCustody::SharedOwned(retained) = owner.inner.operation.as_ref().unwrap()
        else {
            panic!("expected exact shared original custody");
        };
        assert!(Arc::ptr_eq(retained, &original));
        drop(original);
        assert_eq!(
            owner
                .inner
                .operation
                .as_ref()
                .unwrap()
                .guard()
                .status()
                .unwrap()
                .operation_id,
            identity
        );
        assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);

        // The untouched domain closes its actual last guard body on Drop.
        // This does not observe enclosing Arc control free or installed pins.
        drop(owner);
        assert!(supervisor.operation_statuses().unwrap().is_empty());
        assert!(allocator.reserve_resources(0, 6, 4096).is_ok());
    }

    #[test]
    fn rejects_invalid_fixed_envelopes_and_rosters() {
        for cpus in [&[][..], &[1, 2, 3], &[3, 3], &[4, 2], &[0, 1, 2, 3, 4]] {
            assert!(MeasurementCgroupContract::resident(cpus, 1, 1).is_err());
        }
        assert!(MeasurementCgroupContract::resident(&[0], MAX_ACTOR_MEMORY + 1, 1).is_err());
        assert!(MeasurementCgroupContract::resident(&[0], 0, 1).is_err());
        assert!(MeasurementCgroupContract::resident(&[0], 1, 0).is_err());
    }

    #[test]
    fn kernel_affinity_spellings_compare_as_the_same_finite_roster() {
        assert_eq!(cpu_roster("3-4,9-10\n").unwrap(), [3, 4, 9, 10]);
        assert_eq!(cpu_roster("3,4,9,10\n").unwrap(), [3, 4, 9, 10]);
        for malformed in [
            "",
            "0-4294967295",
            "3-2",
            "1,1",
            "3,2",
            "1-4,5",
            "-1",
            "1,,2",
        ] {
            assert!(cpu_roster(malformed).is_err(), "{malformed}");
        }
    }

    #[test]
    fn rejects_foreign_operation_class_before_any_namespace_effect() {
        use crucible_linux_resource::host_services::HostServiceAllocator;
        use crucible_linux_resource::host_supervision::{
            HostOperationBudgets, HostOperationSupervisor,
        };

        let allocator = HostServiceAllocator::new(1, 6, 4096).unwrap();
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let setup = supervisor.begin(HostOperationClass::Setup).unwrap();
        let loan = allocator.reserve_resources(0, 6, 4096).unwrap();
        let contract = MeasurementCgroupContract::resident(&[1], 1, 1).unwrap();

        assert!(matches!(
            MeasurementCgroupOwner::retain_original(loan, contract, &setup),
            Err(MeasurementCgroupError::Original)
        ));
        // No published kernel effect means the actual consumed loan can close.
        assert!(allocator.reserve_resources(0, 6, 4096).is_ok());
    }

    #[test]
    fn owning_preparation_preserves_actual_identity_and_deadline_without_borrow() {
        use crucible_linux_resource::host_services::HostServiceAllocator;
        use crucible_linux_resource::host_supervision::{
            HostOperationBudgets, HostOperationSupervisor,
        };

        fn move_owned<T: Send + 'static>(owner: T) -> T {
            owner
        }

        let allocator = HostServiceAllocator::new(1, 6, 4096).unwrap();
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_secs(1)),
        )
        .unwrap();
        let preparation = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let before = preparation.status().unwrap();
        let loan = allocator.reserve_resources(0, 6, 4096).unwrap();
        let contract = MeasurementCgroupContract::resident(&[1], 1, 1).unwrap();

        let owner = move_owned(
            OwnedMeasurementCgroupOwner::retain_owned(loan, contract, preparation).unwrap(),
        );
        let retained = owner.inner.operation.as_ref().unwrap().guard();
        let after = retained.status().unwrap();
        assert_eq!(after.operation_id, before.operation_id);
        assert_eq!(after.class, before.class);
        assert_eq!(
            after.started_policy_revision,
            before.started_policy_revision
        );
        assert_eq!(
            after.applied_policy_revision,
            before.applied_policy_revision
        );
        let before_deadline = before.effective_deadline.unwrap();
        let after_deadline = after.effective_deadline.unwrap();
        assert_eq!(after_deadline.sources, before_deadline.sources);
        assert!(after_deadline.remaining <= before_deadline.remaining);
        assert!(!after_deadline.remaining.is_zero());
        assert!(allocator.reserve_resources(0, 6, 4096).is_err());
        // This untouched component owns no installed kernel namespace.
        drop(owner);
        assert!(allocator.reserve_resources(0, 6, 4096).is_ok());
    }

    #[test]
    fn owned_scope_keeps_same_cancellation_and_single_use_cleanup() {
        use crucible_linux_resource::host_services::HostServiceAllocator;
        use crucible_linux_resource::host_supervision::{
            HostOperationBudgets, HostOperationSupervisor,
        };

        let allocator = HostServiceAllocator::new(1, 6, 4096).unwrap();
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let preparation = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let contract = MeasurementCgroupContract::resident(&[1], 1, 1).unwrap();
        let loan = allocator.reserve_resources(0, 6, 4096).unwrap();
        let mut owner =
            OwnedMeasurementCgroupOwner::retain_owned(loan, contract, preparation).unwrap();
        supervisor.cancel().unwrap();

        assert!(matches!(
            owner.install(Path::new("/does-not-exist"), "../invalid"),
            Err(MeasurementCgroupError::Supervision(_))
        ));
        owner.retire().unwrap();
        assert_eq!(
            owner
                .inner
                .cleanup
                .as_ref()
                .unwrap()
                .status()
                .unwrap()
                .class,
            HostOperationClass::Cleanup
        );
        assert!(matches!(owner.retire(), Err(MeasurementCgroupError::State)));
        assert!(allocator.reserve_resources(0, 6, 4096).is_err());
        drop(owner);
        assert!(allocator.reserve_resources(0, 6, 4096).is_ok());
    }

    #[test]
    fn original_cancellation_refuses_setup_but_retains_authentic_cleanup() {
        use crucible_linux_resource::host_services::HostServiceAllocator;
        use crucible_linux_resource::host_supervision::{
            HostOperationBudgets, HostOperationSupervisor,
        };

        let allocator = HostServiceAllocator::new(1, 6, 4096).unwrap();
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let preparation = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let loan = allocator.reserve_resources(0, 6, 4096).unwrap();
        let contract = MeasurementCgroupContract::resident(&[1], 1, 1).unwrap();
        let mut owner =
            MeasurementCgroupOwner::retain_original(loan, contract, &preparation).unwrap();
        supervisor.cancel().unwrap();

        // Cancellation precedes interpreting even an invalid path/name. These
        // are real original scope refusals, not simulated installed-domain proof.
        assert!(matches!(
            owner.install(Path::new("/does-not-exist"), "../invalid"),
            Err(MeasurementCgroupError::Supervision(_))
        ));
        owner.retire().unwrap();
        assert_eq!(
            owner.cleanup.as_ref().unwrap().status().unwrap().class,
            HostOperationClass::Cleanup
        );
        assert!(matches!(
            owner.install(Path::new("/does-not-exist"), "unused"),
            Err(MeasurementCgroupError::State)
        ));
        assert!(matches!(owner.retire(), Err(MeasurementCgroupError::State)));
        assert!(allocator.reserve_resources(0, 6, 4096).is_err());
        drop(owner);
        assert!(allocator.reserve_resources(0, 6, 4096).is_ok());
    }

    use crucible_linux_resource::host_services::HostServiceAllocator;
    use crucible_linux_resource::test_support::TestAllocationObserver;
    use std::os::unix::fs::MetadataExt;
    use std::sync::atomic::AtomicBool;

    /// Closed unit-only snapshot, outside allocator hooks. The selected marker
    /// free lets the existing observer sample the actual original account at
    /// this cut. This is not an installed-cgroup or allocator-control-free proof.
    #[derive(Debug)]
    pub(super) struct DropCut<'a> {
        path: &'a Path,
        identity: (u64, u64),
        closed: &'a AtomicBool,
        marker: Option<Box<u64>>,
    }

    impl DropCut<'_> {
        pub(super) fn sample(&mut self) {
            let closed = match std::fs::metadata(self.path) {
                Ok(identity) => (identity.dev(), identity.ino()) != self.identity,
                Err(error) => error.kind() == io::ErrorKind::NotFound,
            };
            self.closed.store(closed, Ordering::SeqCst);
            drop(self.marker.take());
        }
    }

    #[test]
    fn actual_prechild_pin_closes_before_original_credit_refund() {
        check_prechild_drop_cut(false);
    }

    #[test]
    fn original_before_pin_predecessor_fails_the_same_drop_cut() {
        check_prechild_drop_cut(true);
    }

    fn check_prechild_drop_cut(original_first: bool) {
        use crucible_linux_resource::host_supervision::{
            HostOperationBudgets, HostOperationSupervisor,
        };

        let allocator = HostServiceAllocator::new(1, 6, 4096).unwrap();
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let preparation = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let original = allocator.reserve_resources(0, 6, 4096).unwrap();
        let contract = MeasurementCgroupContract::resident(&[1], 1, 1).unwrap();
        let pin: OwnedFd = tempfile::tempfile().unwrap().into();
        let identity = fstat(&pin).unwrap();
        let proc_path = PathBuf::from(format!("/proc/self/fd/{}", pin.as_raw_fd()));
        let closed = AtomicBool::new(false);
        let (marker, selected) =
            TestAllocationObserver::capture(std::mem::size_of::<u64>(), || Box::new(0_u64));
        assert!(selected.is_some());

        let mut owner =
            MeasurementCgroupOwner::retain_original(original, contract, &preparation).unwrap();

        // This private record exercises actual generic FD/credit retirement.
        // It never invokes install or claims cgroup enforcement or birth credit.
        owner.ancestor = Some(LinuxQemuCgroupRoot {
            path: PathBuf::new(),
            directory: pin,
        });
        owner.state = DomainState::Installing;
        owner.drop_cut = Some(DropCut {
            path: &proc_path,
            identity: (identity.st_dev, identity.st_ino),
            closed: &closed,
            marker: Some(marker),
        });
        let (_, observations) = TestAllocationObserver::observe_controls(
            [&allocator, &allocator],
            Some(&closed),
            [selected, None, None],
            || {
                if original_first {
                    // Sole predecessor mutation: refund before closing pins.
                    drop(owner.original.take());
                    owner.drop_cut.as_mut().unwrap().sample();
                    drop(owner.ancestor.take());
                    drop(owner.drop_cut.take());
                }
                drop(owner);
            },
        );
        let observed = observations[0].unwrap();
        let valid = observed.before.original_bytes == [Some(4096), Some(4096)]
            && observed.after.original_bytes == [Some(4096), Some(4096)]
            && observed.before.occupied == Some(true)
            && observed.after.occupied == Some(true);
        assert_eq!(valid, !original_first);
        if original_first {
            assert_eq!(observed.before.original_bytes, [Some(0), Some(0)]);
            assert_eq!(observed.before.occupied, Some(false));
        }
        let recovered = allocator.reserve_resources(0, 6, 4096).unwrap();
        assert_eq!(recovered.resident_bytes(), 4096);
        assert_eq!(recovered.file_descriptors(), 6);
    }

    #[test]
    fn cleanup_control_uses_original_class_policy_after_terminal_preparation() {
        use crucible_linux_resource::host_supervision::{
            HostOperationBudgets, HostOperationSupervisor,
        };

        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let preparation = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let setup = supervisor.begin(HostOperationClass::Setup).unwrap();
        assert!(matches!(
            setup.begin_original_cleanup_control(),
            Err(HostSupervisionError::InvalidBudget)
        ));
        supervisor.cancel().unwrap();

        let (cleanup, allocations) =
            TestAllocationObserver::count(|| preparation.begin_original_cleanup_control().unwrap());
        assert_eq!(cleanup.status().unwrap().class, HostOperationClass::Cleanup);
        assert!(cleanup.status().unwrap().effective_deadline.is_some());
        assert_eq!(allocations.allocations, 0);
        assert_eq!(allocations.reallocations, 0);
        assert!(!allocations.overflow);
        // Three entries fit this actual existing leaf. This local zero count
        // does not fund other rosters or the first supervisor/tree allocation.
    }
}
