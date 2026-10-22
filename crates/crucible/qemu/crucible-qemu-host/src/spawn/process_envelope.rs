//! Binds configured process ceilings to the same retained containment contract.
//!
//! Only the real cgroup child builder seals task limits. Descriptor-only test
//! contracts cannot produce this witness. It carries identity and configured
//! kernel containment facts; metadata credit and complete process admission
//! remain with the original account purpose issuer.

use std::sync::{Arc, Weak};

use super::{AttemptResourceBinding, QemuChildProcessContract, QemuSpawnError};
use std::sync::atomic::Ordering;

const OPEN: u8 = 0;
const REFINING: u8 = 1;
const FROZEN: u8 = 2;
const REFUSED: u8 = 3;

impl AttemptResourceBinding {
    pub(super) fn check_clone_available(&self) -> Result<(), QemuSpawnError> {
        match self.launch_state.load(Ordering::Acquire) {
            OPEN | FROZEN => Ok(()),
            _ => Err(QemuSpawnError::Io {
                operation: "borrow QEMU effective process envelope",
                source: std::io::Error::from_raw_os_error(libc::EBUSY),
            }),
        }
    }

    fn matches_refinement_snapshot(
        &self,
        resident_bytes: u64,
        descriptors: u64,
        main_stack_bytes: Option<u64>,
    ) -> bool {
        self.effective_resident_bytes.load(Ordering::Acquire) == resident_bytes
            && self.effective_file_descriptors.load(Ordering::Acquire) == descriptors
            && super::main_stack::selected_limit(self) == main_stack_bytes
    }

    pub(super) fn refine_descriptor_limit(
        &self,
        expected_resident_bytes: u64,
        expected: u64,
        expected_main_stack_bytes: Option<u64>,
        requested: u64,
    ) -> Result<(), ProcessEnvelopeRefinementError> {
        if requested == libc::RLIM_INFINITY
            || requested < QemuChildProcessContract::required_launch_file_descriptors()
            || requested > expected
        {
            return Err(ProcessEnvelopeRefinementError::DescriptorLimit);
        }
        self.launch_state
            .compare_exchange(OPEN, REFINING, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ProcessEnvelopeRefinementError::Started)?;

        if !self.matches_refinement_snapshot(
            expected_resident_bytes,
            expected,
            expected_main_stack_bytes,
        ) {
            self.launch_state.store(OPEN, Ordering::Release);
            return Err(ProcessEnvelopeRefinementError::Identity);
        }
        self.effective_file_descriptors
            .store(requested, Ordering::Release);
        self.launch_state.store(OPEN, Ordering::Release);
        Ok(())
    }

    pub(super) fn configure_main_stack(&self, bytes: u64) -> std::io::Result<()> {
        self.launch_state
            .compare_exchange(OPEN, REFINING, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| super::main_stack::refused(libc::EBUSY))?;

        // All clones share one once-only choice. Refusing a repeated request
        // preserves the first choice and leaves unrelated refinements available.
        let result =
            self.main_stack_bytes
                .compare_exchange(0, bytes, Ordering::AcqRel, Ordering::Acquire);
        self.launch_state.store(OPEN, Ordering::Release);
        result
            .map(|_| ())
            .map_err(|_| super::main_stack::refused(libc::EALREADY))
    }

    pub(super) fn freeze_for_launch(&self) -> Result<(), QemuSpawnError> {
        match self
            .launch_state
            .compare_exchange(OPEN, FROZEN, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) | Err(FROZEN) => Ok(()),
            Err(_) => Err(QemuSpawnError::Io {
                operation: "close QEMU pre-exec envelope refinement",
                source: std::io::Error::from_raw_os_error(libc::EBUSY),
            }),
        }
    }
}

/// Refuses a stale, started or unsuccessfully refined process envelope.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProcessEnvelopeRefinementError {
    #[error("configured process envelope is stale or unavailable")]
    Identity,
    #[error("process envelope was started, is being refined or already refused")]
    Started,
    #[error("refined memory ceiling must be nonzero and monotonic")]
    Limit,
    #[error("refined descriptor limit must be finite, monotonic and fit fixed launch targets")]
    DescriptorLimit,
    #[error("QEMU memory refinement failed: {0}")]
    Control(#[source] crate::linux_cgroup::LinuxQemuCgroupError),
}

/// Retains the identity and exact configured ceilings of one contained process.
///
/// The weak identity borrows an existing allocation. Its containing original
/// purpose must account for the binding header until this witness is dropped;
/// it cannot treat weak lifetime as an allocation-free retirement.
#[derive(Debug)]
pub(crate) struct ConfiguredProcessEnvelope {
    binding: Weak<AttemptResourceBinding>,
    child_cgroup_device: u64,
    child_cgroup_inode: u64,
    child_user_id: u32,
    child_group_id: u32,
    maximum_vcpus: u32,
    maximum_resident_bytes: u64,
    maximum_tasks: u32,
    maximum_writable_bytes: u64,
    maximum_file_descriptors: u64,
    maximum_locked_bytes: u64,
    main_stack_bytes: Option<u64>,
}

impl QemuChildProcessContract {
    /// Refines the same effective kernel ceiling before the first attempted exec.
    ///
    /// The containing account decides the requested subdivision and performs
    /// its original-operation checks. This method issues no credit. The
    /// shared latch excludes descriptor cloning and spawn during readback.
    /// The requested cap rounds down to the real kernel page size so the
    /// refreshed witness names the enforced limit, not unspendable remainder.
    /// Failed or partial control changes permanently close future launches.
    ///
    /// # Errors
    /// Refuses foreign/stale witnesses, sub-page or increased limits, started
    /// families, and pinned-controller write/readback failure.
    pub(crate) fn refine_configured_process_envelope(
        &self,
        expected: &ConfiguredProcessEnvelope,
        requested: u64,
    ) -> Result<ConfiguredProcessEnvelope, ProcessEnvelopeRefinementError> {
        if !expected.matches_contract(self) {
            return Err(ProcessEnvelopeRefinementError::Identity);
        }
        if requested > self.effective_resident_bytes() {
            return Err(ProcessEnvelopeRefinementError::Limit);
        }
        let requested =
            page_enforced_limit(requested).ok_or(ProcessEnvelopeRefinementError::Limit)?;
        self.attempt_binding
            .launch_state
            .compare_exchange(OPEN, REFINING, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ProcessEnvelopeRefinementError::Started)?;

        // A duplicate may refine the envelope after the initial identity cut.
        // Recheck the entire mutable snapshot while holding the shared latch.
        if !self.attempt_binding.matches_refinement_snapshot(
            expected.maximum_resident_bytes,
            expected.maximum_file_descriptors,
            expected.main_stack_bytes,
        ) {
            self.attempt_binding
                .launch_state
                .store(OPEN, Ordering::Release);
            return Err(ProcessEnvelopeRefinementError::Identity);
        }

        let result = crate::linux_cgroup::tighten_process_envelope(
            self.cgroup_directory
                .as_ref()
                .ok_or(ProcessEnvelopeRefinementError::Identity)?,
            expected.maximum_resident_bytes,
            requested,
        );
        if let Err(error) = result {
            self.attempt_binding
                .launch_state
                .store(REFUSED, Ordering::Release);
            return Err(ProcessEnvelopeRefinementError::Control(error));
        }
        self.attempt_binding
            .effective_resident_bytes
            .store(requested, Ordering::Release);
        self.attempt_binding
            .launch_state
            .store(OPEN, Ordering::Release);
        self.configured_process_envelope()
            .ok_or(ProcessEnvelopeRefinementError::Identity)
    }

    /// Selects a lower finite per-process NOFILE assignment before first exec.
    ///
    /// The containing issuer reserves the descriptor share and all separately
    /// retained host/process tables. This method only binds that request to the
    /// same contract. Every guarded exec installs the shared effective value as
    /// both soft and hard RLIMIT_NOFILE; existing high descriptors are not closed
    /// by lowering a limit and remain the original owner's custody obligation.
    /// No parent limit is changed and no aggregate descriptor credit is issued.
    ///
    /// # Errors
    /// Refuses stale or foreign witnesses, unbounded/increased/below-target
    /// limits, and any refinement after the first attempted exec or refusal.
    pub(crate) fn refine_configured_descriptor_limit(
        &self,
        expected: &ConfiguredProcessEnvelope,
        requested: u64,
    ) -> Result<ConfiguredProcessEnvelope, ProcessEnvelopeRefinementError> {
        if !expected.matches_contract(self) {
            return Err(ProcessEnvelopeRefinementError::Identity);
        }
        self.attempt_binding.refine_descriptor_limit(
            expected.maximum_resident_bytes,
            expected.maximum_file_descriptors,
            expected.main_stack_bytes,
            requested,
        )?;
        self.configured_process_envelope()
            .ok_or(ProcessEnvelopeRefinementError::Identity)
    }

    /// Borrows the real sealed process identity without issuing any credit.
    ///
    /// Returns `None` for descriptor-only fixtures, unavailable shared state,
    /// missing containment/credentials, unreadable child-directory identity,
    /// or unbounded descriptor assignments.
    /// The cgroup builder writes and reads back CPU/memory/swap/task controls;
    /// pre-exec attaches through the pinned `cgroup.procs` before loading code.
    pub(crate) fn configured_process_envelope(&self) -> Option<ConfiguredProcessEnvelope> {
        self.attempt_binding.check_clone_available().ok()?;
        let (child_cgroup_device, child_cgroup_inode) =
            child_directory_identity(self.cgroup_directory.as_ref()?)?;
        let credentials = self.credentials?;
        let maximum_tasks = self.maximum_tasks?;
        let maximum_file_descriptors = self.effective_file_descriptors()?;
        if maximum_file_descriptors == libc::RLIM_INFINITY
            || maximum_file_descriptors < Self::required_launch_file_descriptors()
            || self.maximum_locked_bytes == libc::RLIM_INFINITY
        {
            return None;
        }
        Some(ConfiguredProcessEnvelope {
            binding: Arc::downgrade(&self.attempt_binding),
            child_cgroup_device,
            child_cgroup_inode,
            child_user_id: credentials.user_id,
            child_group_id: credentials.group_id,
            maximum_vcpus: self.maximum_vcpus,
            maximum_resident_bytes: self.effective_resident_bytes(),
            maximum_tasks,
            maximum_writable_bytes: self.maximum_writable_bytes,
            maximum_file_descriptors,
            maximum_locked_bytes: self.maximum_locked_bytes,
            main_stack_bytes: self.main_stack_limit(),
        })
    }
}

// This reads the selected child descriptor already owned by the sealed
// contract. It neither opens a path nor borrows the workload parent directory.
fn child_directory_identity(directory: &std::os::fd::OwnedFd) -> Option<(u64, u64)> {
    let metadata = rustix::fs::fstat(directory).ok()?;
    if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::Directory {
        return None;
    }
    let device = metadata.st_dev;
    let inode = metadata.st_ino;
    (device != 0 && inode != 0).then_some((device, inode))
}

// memory.max is page-granular. Leave the tail unassigned rather than claim a
// requested byte count the authenticated kernel readback cannot represent.
fn page_enforced_limit(requested: u64) -> Option<u64> {
    let page_bytes = u64::try_from(rustix::param::page_size()).ok()?;
    requested
        .checked_div(page_bytes)?
        .checked_mul(page_bytes)
        .filter(|bytes| *bytes != 0)
}

impl ConfiguredProcessEnvelope {
    /// Returns the existing binding allocation retained by this weak witness.
    ///
    /// This extent must be assigned before the real contract allocation; it is
    /// shared with its stage witness and must not be charged twice.
    pub(crate) fn retained_binding_bytes() -> Option<u64> {
        super::QemuProcessStageBinding::retained_control_bytes()
    }

    /// Verifies both live allocation identity and the same configured ceilings.
    pub(crate) fn same_process_as(&self, other: &Self) -> bool {
        let (Some(_left), Some(_right)) = (self.binding.upgrade(), other.binding.upgrade()) else {
            return false;
        };
        matches!(_left.launch_state.load(Ordering::Acquire), OPEN | FROZEN)
            && _left.effective_resident_bytes.load(Ordering::Acquire) == self.maximum_resident_bytes
            && _left.effective_file_descriptors.load(Ordering::Acquire)
                == self.maximum_file_descriptors
            && Weak::ptr_eq(&self.binding, &other.binding)
            && self.child_cgroup_device == other.child_cgroup_device
            && self.child_cgroup_inode == other.child_cgroup_inode
            && self.child_user_id == other.child_user_id
            && self.child_group_id == other.child_group_id
            && self.maximum_vcpus == other.maximum_vcpus
            && self.maximum_resident_bytes == other.maximum_resident_bytes
            && self.maximum_tasks == other.maximum_tasks
            && self.maximum_writable_bytes == other.maximum_writable_bytes
            && self.maximum_file_descriptors == other.maximum_file_descriptors
            && self.maximum_locked_bytes == other.maximum_locked_bytes
            && self.main_stack_bytes == other.main_stack_bytes
            && self.main_stack_bytes == super::main_stack::selected_limit(&_left)
    }

    /// Verifies that the current contract still names this exact process owner.
    pub(crate) fn matches_contract(&self, contract: &QemuChildProcessContract) -> bool {
        contract
            .configured_process_envelope()
            .is_some_and(|current| self.same_process_as(&current))
    }

    /// Returns the non-root credential assignment sealed by this actual contract.
    pub(crate) const fn child_credential_ids(&self) -> (u32, u32) {
        (self.child_user_id, self.child_group_id)
    }

    /// Returns the device of the pinned selected child cgroup directory.
    ///
    /// This is a physical identity corroboration under the same binding, not
    /// a capability, a workload-root identity, or a resource entitlement.
    pub(crate) const fn child_cgroup_device(&self) -> u64 {
        self.child_cgroup_device
    }

    /// Returns the inode of the same pinned selected child cgroup directory.
    pub(crate) const fn child_cgroup_inode(&self) -> u64 {
        self.child_cgroup_inode
    }

    pub(crate) const fn maximum_vcpus(&self) -> u32 {
        self.maximum_vcpus
    }

    pub(crate) const fn maximum_resident_bytes(&self) -> u64 {
        self.maximum_resident_bytes
    }

    pub(crate) const fn maximum_tasks(&self) -> u32 {
        self.maximum_tasks
    }

    pub(crate) const fn maximum_writable_bytes(&self) -> u64 {
        self.maximum_writable_bytes
    }

    pub(crate) const fn maximum_file_descriptors(&self) -> u64 {
        self.maximum_file_descriptors
    }

    pub(crate) const fn maximum_locked_bytes(&self) -> u64 {
        self.maximum_locked_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These identity controls deliberately issue no configured contract or
    // process purpose. Only the real cgroup builder may supply that provenance.
    fn identity(binding: &Arc<AttemptResourceBinding>) -> ConfiguredProcessEnvelope {
        ConfiguredProcessEnvelope {
            binding: Arc::downgrade(binding),
            child_cgroup_device: 1,
            child_cgroup_inode: 2,
            child_user_id: 1000,
            child_group_id: 1000,
            maximum_vcpus: 2,
            maximum_resident_bytes: 4096,
            maximum_tasks: 8,
            maximum_writable_bytes: 8192,
            maximum_file_descriptors: 32,
            maximum_locked_bytes: 0,
            main_stack_bytes: None,
        }
    }

    #[test]
    fn selecting_main_stack_invalidates_an_earlier_process_observation() {
        let binding = Arc::new(AttemptResourceBinding::new(4096, Some(32)));
        let earlier = identity(&binding);
        let same_earlier = identity(&binding);
        assert!(earlier.same_process_as(&same_earlier));

        binding.configure_main_stack(2 * 1024 * 1024).unwrap();
        assert!(!earlier.same_process_as(&same_earlier));

        let mut current = identity(&binding);
        current.main_stack_bytes = Some(2 * 1024 * 1024);
        assert!(current.same_process_as(&current));
        assert!(!earlier.same_process_as(&current));
    }

    #[test]
    fn equal_limits_do_not_replace_same_live_process_identity() {
        let original = Arc::new(AttemptResourceBinding::new(4096, Some(32)));
        let foreign = Arc::new(AttemptResourceBinding::new(4096, Some(32)));
        let saved = identity(&original);
        let same = identity(&original);

        assert!(saved.same_process_as(&same));
        assert!(!saved.same_process_as(&identity(&foreign)));
        drop(original);
        assert!(!saved.same_process_as(&same));
    }

    #[test]
    fn selected_child_identity_uses_retained_directory_not_parent_or_path() {
        let parent = tempfile::tempdir().unwrap();
        let child_path = parent.path().join("selected");
        std::fs::create_dir(&child_path).unwrap();
        let parent_fd: std::os::fd::OwnedFd = std::fs::File::open(parent.path()).unwrap().into();
        let child_fd: std::os::fd::OwnedFd = std::fs::File::open(&child_path).unwrap().into();
        let saved = child_directory_identity(&child_fd).unwrap();
        let duplicate = child_fd.try_clone().unwrap();

        // Ordinary directories exercise descriptor identity only. They cannot
        // issue a configured cgroup contract or a process purpose.
        std::fs::rename(&child_path, parent.path().join("retained")).unwrap();
        std::fs::create_dir(&child_path).unwrap();
        let replacement: std::os::fd::OwnedFd = std::fs::File::open(&child_path).unwrap().into();

        assert_eq!(child_directory_identity(&duplicate), Some(saved));
        assert_ne!(child_directory_identity(&parent_fd), Some(saved));
        assert_ne!(child_directory_identity(&replacement), Some(saved));
    }

    #[test]
    fn same_attempt_and_caps_cannot_replace_child_directory_identity() {
        let binding = Arc::new(AttemptResourceBinding::new(4096, Some(32)));
        let saved = identity(&binding);
        let mut changed = identity(&binding);

        assert_eq!(saved.child_cgroup_device(), 1);
        assert_eq!(saved.child_cgroup_inode(), 2);
        changed.child_cgroup_inode += 1;
        assert!(!saved.same_process_as(&changed));
        changed.child_cgroup_inode = saved.child_cgroup_inode;
        changed.child_cgroup_device += 1;
        assert!(!saved.same_process_as(&changed));

        let (socket, _) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(child_directory_identity(&socket.into()).is_none());
    }

    #[test]
    fn retained_identity_does_not_waive_changed_containment_limits() {
        let original = Arc::new(AttemptResourceBinding::new(4096, Some(32)));
        let saved = identity(&original);
        let mut changed = identity(&original);
        changed.maximum_resident_bytes += 1;

        assert!(!saved.same_process_as(&changed));
        changed.maximum_resident_bytes = saved.maximum_resident_bytes;
        changed.maximum_tasks += 1;
        assert!(!saved.same_process_as(&changed));
    }

    #[test]
    fn shared_binding_freezes_before_exec_and_never_renews() {
        let binding = AttemptResourceBinding::new(4096, Some(32));
        assert!(binding.freeze_for_launch().is_ok());
        assert!(binding.freeze_for_launch().is_ok());
        assert_eq!(binding.launch_state.load(Ordering::Acquire), FROZEN);
        assert!(
            binding
                .launch_state
                .compare_exchange(OPEN, REFINING, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        );

        let refused = AttemptResourceBinding::new(4096, Some(32));
        refused.launch_state.store(REFUSED, Ordering::Release);
        assert!(refused.freeze_for_launch().is_err());
        assert!(refused.check_clone_available().is_err());
    }

    #[test]
    fn refinement_in_flight_excludes_exec_and_cloning() {
        let binding = AttemptResourceBinding::new(4096, Some(32));
        binding
            .launch_state
            .compare_exchange(OPEN, REFINING, Ordering::AcqRel, Ordering::Acquire)
            .unwrap();

        assert!(binding.freeze_for_launch().is_err());
        assert!(binding.check_clone_available().is_err());
        assert_eq!(binding.launch_state.load(Ordering::Acquire), REFINING);
    }

    #[test]
    fn old_snapshot_cannot_certify_a_changed_shared_effective_limit() {
        let binding = Arc::new(AttemptResourceBinding::new(4096, Some(32)));
        let old = identity(&binding);
        binding
            .effective_resident_bytes
            .store(2048, Ordering::Release);
        let mut current = identity(&binding);
        current.maximum_resident_bytes = 2048;

        assert!(!old.same_process_as(&old));
        assert!(!old.same_process_as(&current));
        assert!(current.same_process_as(&current));
    }

    #[test]
    fn actual_contract_duplicates_read_the_same_effective_storage() {
        let (control, _) = std::os::unix::net::UnixStream::pair().unwrap();
        let event = rustix::event::eventfd(0, rustix::event::EventfdFlags::NONBLOCK).unwrap();
        let original = QemuChildProcessContract::for_test(control.into(), event, 4096);
        let duplicate = original.try_clone_for_attempt_generation().unwrap();
        let authored = original.maximum_resident_bytes;

        // Exercise shared storage only; these fixtures cannot authenticate a
        // configured envelope or issue a process purpose.
        original
            .attempt_binding
            .effective_resident_bytes
            .store(2048, Ordering::Release);
        assert_eq!(duplicate.effective_resident_bytes(), 2048);
        assert_eq!(original.effective_resident_bytes(), 2048);
        assert_eq!(original.maximum_resident_bytes, authored);
        assert!(duplicate.configured_process_envelope().is_none());
        assert!(ConfiguredProcessEnvelope::retained_binding_bytes().unwrap() > 16);
    }

    #[test]
    fn descriptor_refinement_preserves_memory_and_invalidates_old_snapshot() {
        let binding = Arc::new(AttemptResourceBinding::new(4096, Some(32)));
        let old = identity(&binding);
        let duplicate = Arc::clone(&binding);

        binding.refine_descriptor_limit(4096, 32, None, 24).unwrap();
        let mut current = identity(&binding);
        current.maximum_file_descriptors = 24;

        assert_eq!(
            duplicate.effective_file_descriptors.load(Ordering::Acquire),
            24
        );
        assert_eq!(
            binding.effective_resident_bytes.load(Ordering::Acquire),
            4096
        );
        assert!(!old.same_process_as(&old));
        assert!(current.same_process_as(&current));
        assert_eq!(current.child_cgroup_device(), old.child_cgroup_device());
        assert_eq!(current.child_cgroup_inode(), old.child_cgroup_inode());
        assert!(matches!(
            binding.refine_descriptor_limit(4096, 32, None, 20),
            Err(ProcessEnvelopeRefinementError::Identity)
        ));
        assert_eq!(
            binding.effective_file_descriptors.load(Ordering::Acquire),
            24
        );
    }

    #[test]
    fn descriptor_refinement_cannot_apply_to_a_changed_memory_snapshot() {
        let binding = AttemptResourceBinding::new(4096, Some(32));
        binding
            .effective_resident_bytes
            .store(2048, Ordering::Release);

        assert!(matches!(
            binding.refine_descriptor_limit(4096, 32, None, 24),
            Err(ProcessEnvelopeRefinementError::Identity)
        ));
        assert_eq!(
            binding.effective_file_descriptors.load(Ordering::Acquire),
            32
        );
        assert_eq!(binding.launch_state.load(Ordering::Acquire), OPEN);
    }

    #[test]
    fn descriptor_refinement_rejects_intervening_stack_selection() {
        let binding = Arc::new(AttemptResourceBinding::new(4096, Some(32)));
        let observed = identity(&binding);
        assert!(observed.same_process_as(&observed));

        // This deterministic interleaving occurs after the outer identity cut
        // and before descriptor refinement acquires the same shared latch.
        binding.configure_main_stack(2 * 1024 * 1024).unwrap();
        let result = binding.refine_descriptor_limit(
            observed.maximum_resident_bytes,
            observed.maximum_file_descriptors,
            observed.main_stack_bytes,
            24,
        );

        assert!(matches!(
            result,
            Err(ProcessEnvelopeRefinementError::Identity)
        ));
        assert_eq!(
            binding.effective_file_descriptors.load(Ordering::Acquire),
            32
        );
        assert_eq!(binding.launch_state.load(Ordering::Acquire), OPEN);
        assert_eq!(
            super::super::main_stack::selected_limit(&binding),
            Some(2 * 1024 * 1024)
        );

        binding
            .refine_descriptor_limit(4096, 32, Some(2 * 1024 * 1024), 24)
            .unwrap();
        assert_eq!(
            binding.effective_file_descriptors.load(Ordering::Acquire),
            24
        );
    }

    #[test]
    fn memory_refinement_rejects_intervening_stack_selection() {
        let binding = Arc::new(AttemptResourceBinding::new(4096, Some(32)));
        let observed = identity(&binding);
        assert!(observed.same_process_as(&observed));

        binding.configure_main_stack(2 * 1024 * 1024).unwrap();
        binding
            .launch_state
            .compare_exchange(OPEN, REFINING, Ordering::AcqRel, Ordering::Acquire)
            .unwrap();
        // Exercise the exact locked precondition before the real cgroup write;
        // this identity fixture cannot issue a configured process witness.
        assert!(!binding.matches_refinement_snapshot(
            observed.maximum_resident_bytes,
            observed.maximum_file_descriptors,
            observed.main_stack_bytes,
        ));
        assert!(binding.matches_refinement_snapshot(4096, 32, Some(2 * 1024 * 1024)));
        assert_eq!(
            binding.effective_resident_bytes.load(Ordering::Acquire),
            4096
        );
    }

    #[test]
    fn descriptor_refinement_refuses_invalid_or_started_assignments() {
        let binding = AttemptResourceBinding::new(4096, Some(32));
        let floor = QemuChildProcessContract::required_launch_file_descriptors();

        for requested in [0, floor - 1, 33, libc::RLIM_INFINITY] {
            assert!(matches!(
                binding.refine_descriptor_limit(4096, 32, None, requested),
                Err(ProcessEnvelopeRefinementError::DescriptorLimit)
            ));
            assert_eq!(
                binding.effective_file_descriptors.load(Ordering::Acquire),
                32
            );
            assert_eq!(binding.launch_state.load(Ordering::Acquire), OPEN);
        }
        binding
            .refine_descriptor_limit(4096, 32, None, floor)
            .unwrap();
        binding.freeze_for_launch().unwrap();
        assert!(matches!(
            binding.refine_descriptor_limit(4096, floor, None, floor),
            Err(ProcessEnvelopeRefinementError::Started)
        ));
        assert_eq!(
            binding.effective_file_descriptors.load(Ordering::Acquire),
            floor
        );
    }

    #[test]
    fn actual_contract_duplicates_share_descriptor_limit_without_issuing_identity() {
        let (control, _) = std::os::unix::net::UnixStream::pair().unwrap();
        let event = rustix::event::eventfd(0, rustix::event::EventfdFlags::NONBLOCK).unwrap();
        let mut original = QemuChildProcessContract::for_test(control.into(), event, 4096);
        original.maximum_file_descriptors = Some(32);
        original.attempt_binding = Arc::new(AttemptResourceBinding::new(4096, Some(32)));
        let duplicate = original.try_clone_for_attempt_generation().unwrap();

        original
            .attempt_binding
            .refine_descriptor_limit(4096, 32, None, 24)
            .unwrap();

        assert_eq!(original.effective_file_descriptors(), Some(24));
        assert_eq!(duplicate.effective_file_descriptors(), Some(24));
        assert_eq!(original.maximum_file_descriptors, Some(32));
        assert!(original.configured_process_envelope().is_none());
        assert!(duplicate.configured_process_envelope().is_none());
    }

    #[test]
    fn unaligned_account_remainder_never_becomes_an_unenforced_cap() {
        let page_bytes = rustix::param::page_size() as u64;
        let total = 3 * page_bytes;
        let outside_host = 1;
        let account_remainder = total - outside_host;

        let enforced = page_enforced_limit(account_remainder).unwrap();

        assert_eq!(enforced, 2 * page_bytes);
        assert!(enforced < account_remainder);
        assert!(enforced + outside_host <= total);
        assert_eq!(enforced % page_bytes, 0);
        assert_eq!(page_enforced_limit(page_bytes), Some(page_bytes));
        assert_eq!(page_enforced_limit(page_bytes - 1), None);
        assert_eq!(page_enforced_limit(0), None);
    }

    #[test]
    fn descriptor_only_fixture_cannot_issue_configured_envelope() {
        let (control, _) = std::os::unix::net::UnixStream::pair().unwrap();
        let event = rustix::event::eventfd(0, rustix::event::EventfdFlags::NONBLOCK).unwrap();
        let fixture = QemuChildProcessContract::for_test(control.into(), event, 4096);

        assert!(fixture.configured_process_envelope().is_none());
        assert!(
            fixture
                .try_clone_for_attempt_generation()
                .unwrap()
                .configured_process_envelope()
                .is_none()
        );
    }
}
