//! Setup completion for the QEMU plugin control protocol.
//!
//! The setup path borrows the native owner's current `Setup` roles, maps shared memory
//! region for exactly the advertised byte length, validates the region header,
//! authenticates the current-version sealed plugin plan, and arms the wake
//! fd for later event-loop registration. The caller then proves plugin callback
//! ownership, registers the wake fd, and sends `SetupAck(0)` with the returned
//! completion token. Descriptor validity comes from the fixed SCM_RIGHTS
//! handoff authenticated by native preinit; mmap lifetime is owned by [`PluginSetupCompletion`]
//! token.

#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};

use thiserror::Error;

#[cfg(unix)]
use crucible_qemu_protocol::{
    DescriptorHandoverError, SETUP_ACK_STATUS_READY, SETUP_ACK_STATUS_SETUP_FAILED,
    SetupCompletionError,
    app_random_branch_plan::AppRandomBranchPlan,
    plugin_send_setup_ack,
    plugin_setup_plan::{PLUGIN_SETUP_PLAN_MAX_BYTES, PluginSetupPlan, PluginSetupPlanError},
    selectable_catalog_plan::SelectableCatalogPlan,
};
#[cfg(all(test, unix))]
use crucible_qemu_protocol::{ReceivedSetup, recv_setup_with_descriptors};
#[cfg(unix)]
use crucible_qemu_shmem::{
    MappedSetupView, RegionLayout, RegionSetupValidationError, SetupRegionMapError,
    ValidatedSetupRegion,
};

#[cfg(unix)]
use crate::{
    PluginCallbackCapabilities, PluginControlHandshake, QemuRegisterWakeFdFn,
    RequiredOwnedCallbacksRegistered, shmem_ordering::PluginShmemOrdering,
};

#[cfg(unix)]
mod boot_barrier;
#[cfg(unix)]
mod mapping;
#[cfg(unix)]
pub use boot_barrier::PluginSetupBootBarrierError;
#[cfg(unix)]
mod failure_ack;
#[cfg(unix)]
pub use failure_ack::{PluginSetupFailureStage, send_callback_registration_failure_ack};

/// An eventfd descriptor armed for setup-complete wake handling.
#[cfg(unix)]
#[derive(Debug)]
pub struct ArmedWakeFd {
    fd: crate::startup_source::SetupDescriptor,
}

#[cfg(unix)]
impl ArmedWakeFd {
    /// Arms an owned wake fd for run-loop integration.
    ///
    /// The current implementation configures close-on-exec and nonblocking
    /// operation on the descriptor received through the validated setup handoff.
    /// Linux exposes no stable descriptor-identity query for eventfd, so the
    /// implementation proves non-semaphore eventfd behavior by writing counters
    /// one and two, reading the aggregated value three, and proving the counter
    /// empty again. Non-Linux builds retain only the empty nonblocking-descriptor
    /// check for portable model tests; production QEMU activation remains Linux.
    /// Call [`Self::register_with_qemu`] before sending `SetupAck(0)`.
    ///
    /// # Errors
    ///
    /// Returns [`WakeFdArmError`] when descriptor flags cannot be read or
    /// updated.
    pub fn arm(fd: OwnedFd) -> Result<Self, WakeFdArmError> {
        set_close_on_exec(fd.as_raw_fd())?;
        set_nonblocking(fd.as_raw_fd())?;
        validate_wake_descriptor(fd.as_raw_fd())?;
        Ok(Self { fd: fd.into() })
    }

    // The native view arrives already configured by its authentic owner. Inspect
    // its flags and eventfd behavior without mutating descriptor/OFD flags.
    pub(crate) fn arm_role(
        fd: crate::startup_source::SetupDescriptor,
    ) -> Result<Self, WakeFdArmError> {
        if fd.is_native() {
            // A malformed provider cannot make the empty-counter check block.
            // SAFETY: these queries inspect the still-native-owned descriptor.
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
            // SAFETY: the same native owner keeps this descriptor live for inspection.
            let descriptor_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
            if flags < 0
                || descriptor_flags < 0
                || flags & libc::O_NONBLOCK == 0
                || descriptor_flags & libc::FD_CLOEXEC == 0
            {
                return Err(WakeFdArmError::Fcntl {
                    operation: "validate native wake role flags",
                    errno: if flags < 0 || descriptor_flags < 0 {
                        last_errno()
                    } else {
                        libc::EINVAL
                    },
                });
            }
            validate_wake_descriptor(fd.as_raw_fd())?;
            Ok(Self { fd })
        } else {
            let owned = fd.into_owned().ok_or(WakeFdArmError::Fcntl {
                operation: "owned wake role is absent",
                errno: libc::EBADF,
            })?;
            Self::arm(owned)
        }
    }

    /// Returns the raw descriptor number for QEMU registration.
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Registers the armed wake fd with QEMU's main-loop wake surface.
    ///
    /// # Errors
    ///
    /// Returns [`WakeFdRegisterError::Rejected`] when QEMU rejects the armed
    /// descriptor.
    pub fn register_with_qemu(
        &self,
        register_wake_fd: QemuRegisterWakeFdFn,
    ) -> Result<RegisteredWakeFd, WakeFdRegisterError> {
        let status = register_wake_fd(self.as_raw_fd());
        if status == 0 {
            Ok(RegisteredWakeFd {
                fd: self.as_raw_fd(),
            })
        } else {
            Err(WakeFdRegisterError::Rejected { status })
        }
    }
}

#[cfg(unix)]
pub(crate) fn signal_teardown_wake_fd(fd: RawFd) -> Result<(), WakeFdSignalError> {
    let value = 1_u64;
    loop {
        // SAFETY: callers retain the armed eventfd while this function runs,
        // and `value` is readable for exactly the eventfd counter width.
        let written = unsafe {
            libc::write(
                fd,
                std::ptr::from_ref(&value).cast::<libc::c_void>(),
                core::mem::size_of::<u64>(),
            )
        };
        if written == core::mem::size_of::<u64>() as isize {
            return Ok(());
        }
        if written < 0 {
            let errno = last_errno();
            if errno == libc::EINTR {
                continue;
            }
            return Err(WakeFdSignalError::Write { errno });
        }
        return Err(WakeFdSignalError::ShortWrite {
            bytes_written: written,
        });
    }
}

/// Typed evidence that an armed wake fd was registered with QEMU.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisteredWakeFd {
    fd: RawFd,
}

#[cfg(unix)]
impl RegisteredWakeFd {
    /// Returns the registered descriptor number.
    #[must_use]
    pub const fn as_raw_fd(self) -> RawFd {
        self.fd
    }
}

/// Typed evidence that the plugin completed setup before acknowledging readiness.
///
/// The mapped shared-memory region stays live while this token is live; callers
/// keep it for the plugin process lifetime before any callback touches shmem.
#[cfg(unix)]
pub struct PluginSetupCompletion {
    mapped_region: mapping::SetupMappingView,
    validated_region: ValidatedSetupRegion,
    validated_layout: RegionLayout,
    shared_memory_device: u64,
    shared_memory_inode: u64,
    wake_fd: ArmedWakeFd,
    app_random_branch_plan: AppRandomBranchPlan,
    selectable_catalog_plan: Option<SelectableCatalogPlan>,
    registered_wake_fd: Option<RegisteredWakeFd>,
    process_generation: u64,
    startup_source: Option<crate::startup_source::InstallerStartupSource>,
    #[cfg(test)]
    refused_device_digest_workspace: Option<crate::device_digest_workspace::DeviceDigestWorkspace>,
    device_digest_workspace: Option<(
        crucible_qemu_protocol::DeviceDigestWorkspaceBinding,
        crate::startup_source::SetupDescriptor,
    )>,
}

#[cfg(unix)]
impl PluginSetupCompletion {
    pub(crate) fn retain_startup_source(
        &mut self,
        source: crate::startup_source::InstallerStartupSource,
    ) {
        self.startup_source = Some(source);
    }

    /// Admits the complete configured callback allocation roster before its birth.
    ///
    /// # Errors
    /// Refuses missing original custody or the actual native containing-purpose
    /// reservation. The same Source retains any failed debit until retirement.
    pub(crate) fn reserve_runtime_allocations(
        &mut self,
        requests: &crate::runtime::prebirth::RuntimeAllocationRequests,
    ) -> Result<(), crate::StartupSourceError> {
        self.startup_source
            .as_mut()
            .ok_or(crate::StartupSourceError::Ownership {
                reason: "initial installer Source is absent",
            })?
            .reserve_runtime_allocations(requests)
    }

    /// Borrows the authentic before-birth command storage claim.
    ///
    /// # Errors
    /// Refuses missing installing Source, claim or containing Runtime custody.
    pub(crate) fn command_storage_material(
        &self,
    ) -> Result<
        (
            u64,
            *mut crate::startup_source::runtime_purpose::RuntimePurpose,
            *mut crate::startup_source::runtime_purpose::CommandClaim,
        ),
        crate::StartupSourceError,
    > {
        self.original_startup()?.command_storage_material()
    }

    /// Borrows the genuine distinct before-birth callback-child claim.
    ///
    /// # Errors
    /// Refuses missing installing Source, child claim or containing custody.
    pub(crate) fn callback_child_material(
        &self,
    ) -> Result<
        (
            u64,
            *mut crate::startup_source::runtime_purpose::RuntimePurpose,
            *mut crate::startup_source::runtime_purpose::CallbackChildClaim,
        ),
        crate::StartupSourceError,
    > {
        self.original_startup()?.callback_child_material()
    }

    /// Borrows both real required-role claims under the same installing Source.
    ///
    /// # Errors
    /// Refuses missing Source, claims or installing admission.
    pub(crate) fn required_worker_material(
        &self,
    ) -> Result<crate::runtime::required_workers::abi::Material, crate::StartupSourceError> {
        self.original_startup()?.required_worker_material()
    }

    /// Attempts actual excluded-creator rollback without completing any worker.
    pub(crate) fn return_unborn_required_workers(&mut self) -> i32 {
        match self.startup_source.as_mut() {
            Some(source) => source.return_unborn_required_workers(),
            None => -libc::ENOKEY,
        }
    }

    /// Borrows the genuine optional worker claim from the same installing Source.
    ///
    /// # Errors
    /// Refuses missing original installation or an absent configured worker role.
    pub(crate) fn fingerprint_worker_material(
        &self,
    ) -> Result<
        (
            u64,
            *mut crate::startup_source::runtime_purpose::RuntimePurpose,
            *mut crate::startup_source::runtime_purpose::WorkerClaim,
        ),
        crate::StartupSourceError,
    > {
        self.original_startup()?.fingerprint_worker_material()
    }

    /// Projects the same terminal endpoint owner before a native worker is born.
    ///
    /// # Errors
    /// Refuses absent actual Source/runtime custody or the matched terminal SDK.
    pub(crate) fn runtime_interrupt_handle(
        &self,
    ) -> Result<crate::startup_source::runtime_purpose::RuntimeInterrupt, crate::StartupSourceError>
    {
        self.original_startup()?.runtime_interrupt_handle()
    }

    /// Rechecks retained runtime allocation custody without temporal admission.
    ///
    /// # Errors
    /// Preserves missing Source or the native retained-accounting refusal.
    pub(crate) fn check_runtime_allocations(&self) -> Result<(), crate::StartupSourceError> {
        self.original_startup()?.check_runtime_allocations()
    }

    /// Checks installing admission and preissued runtime storage before effects.
    ///
    /// # Errors
    /// Preserves the genuine installing Source refusal or retained-accounting
    /// mismatch. The lifetime accounting check does not supply operation time.
    pub(crate) fn check_runtime_installation(&self) -> Result<(), crate::StartupSourceError> {
        self.original_startup()?.check_runtime_installation()
    }

    /// Runs one actor registration/birth exchange under the same installing Source.
    ///
    /// # Errors
    /// Preserves missing custody or the actual exchange/original refusal. Native
    /// outputs must already be retained before the independent postcut can fail.
    pub(crate) fn with_ram_actor_purposes(
        &self,
        exchange: impl FnOnce(u64, *mut std::ffi::c_void, *mut std::ffi::c_void) -> i32,
    ) -> Result<(), crate::StartupSourceError> {
        self.original_startup()?.with_ram_actor_purposes(exchange)
    }

    /// Observes the native owner's terminal shutdown without mutating a borrow.
    ///
    /// # Errors
    /// Refuses missing Source custody or a rejected native journal observation.
    pub(crate) fn interrupt_runtime_reader(&self) -> Result<bool, crate::StartupSourceError> {
        self.original_startup()?.interrupt_runtime_reader()
    }

    pub(crate) fn check_original_startup(&self) -> Result<(), crate::StartupSourceError> {
        self.original_startup()?.check()
    }

    /// Admits the configured seven fixed controls before callback runtime birth.
    ///
    /// # Errors
    /// Refuses absent original custody, unavailable SDK or actual native admission.
    pub(crate) fn reserve_installer_control_purpose(
        &mut self,
    ) -> Result<(), crate::StartupSourceError> {
        self.startup_source
            .as_mut()
            .ok_or(crate::StartupSourceError::Ownership {
                reason: "initial installer Source is absent",
            })?
            .reserve_installer_control_purpose()
    }

    /// Rechecks the same fixed-control holder before managed controller effects.
    ///
    /// # Errors
    /// Preserves missing Source or the actual native purpose/original refusal.
    pub(crate) fn require_installer_control_purpose(
        &self,
    ) -> Result<(), crate::ram_error::RamError> {
        self.original_startup()
            .map_err(crate::ram_error::RamError::InstallerSource)?
            .require_installer_control_purpose()
    }

    pub(crate) fn original_startup_slice(
        &self,
    ) -> Result<std::time::Duration, crate::StartupSourceError> {
        self.original_startup()?.wait_slice()
    }

    #[cfg(not(test))]
    pub(crate) fn complete_original_startup_registration(
        &mut self,
    ) -> Result<(), crate::StartupSourceError> {
        self.startup_source
            .as_mut()
            .ok_or(crate::StartupSourceError::Ownership {
                reason: "initial installer Source is absent",
            })?
            .registration_complete()
    }

    fn original_startup(
        &self,
    ) -> Result<&crate::startup_source::InstallerStartupSource, crate::StartupSourceError> {
        self.startup_source
            .as_ref()
            .ok_or(crate::StartupSourceError::Ownership {
                reason: "initial installer Source is absent",
            })
    }

    /// Rejects extra or absent workspace resources before callback allocation.
    pub(crate) fn validate_device_digest_workspace_mode(
        &self,
        enabled: bool,
        process_generation: u64,
    ) -> Result<(), crate::DeviceDigestWorkspaceError> {
        if self.process_generation != process_generation
            || self.device_digest_workspace.is_some() != enabled
        {
            return Err(crate::DeviceDigestWorkspaceError::Ownership {
                reason: "workspace selection or process generation differs from installation",
            });
        }
        Ok(())
    }

    /// Consumes only the explicit local descriptor fixture's fixed handover.
    #[cfg(test)]
    pub(crate) fn take_device_digest_workspace(
        &mut self,
        _plugin_id: crate::QemuPluginId,
        process_generation: u64,
    ) -> Result<
        crate::device_digest_workspace::DeviceDigestWorkspace,
        crate::DeviceDigestWorkspaceError,
    > {
        if self.refused_device_digest_workspace.is_some() {
            return Err(crate::DeviceDigestWorkspaceError::Ownership {
                reason: "the local workspace fixture remains refused or uncertain",
            });
        }
        if self.process_generation != process_generation {
            return Err(crate::DeviceDigestWorkspaceError::Ownership {
                reason: "setup process generation differs from installation",
            });
        }
        let original = self
            .original_startup()
            .map_err(|source| crate::DeviceDigestWorkspaceError::StartupSource { source })?;
        original
            .check()
            .map_err(|source| crate::DeviceDigestWorkspaceError::StartupSource { source })?;
        let (binding, descriptor) = self.device_digest_workspace.take().ok_or(
            crate::DeviceDigestWorkspaceError::Ownership {
                reason: "fingerprint-enabled setup lacks its compulsory workspace",
            },
        )?;
        match crate::device_digest_workspace::DeviceDigestWorkspace::prepare_fixture(
            binding, descriptor,
        ) {
            Ok(workspace) => Ok(workspace),
            Err(failure) => {
                let source = failure.source;
                // This explicit local fixture retains its refused descriptor;
                // it neither issues nor repairs production Source ownership.
                self.refused_device_digest_workspace = Some(failure.workspace);
                Err(source)
            }
        }
    }

    /// Returns the mapped shared-memory region.
    #[must_use]
    pub fn mapped_region(&self) -> &MappedSetupView {
        self.mapped_region.view()
    }

    /// Returns mutable wire access for disjoint typed views.
    pub(crate) fn mapped_region_mut(&mut self) -> &mut MappedSetupView {
        self.mapped_region.view_mut()
    }

    /// Borrows disjoint wire access and the same authentic installer for postcuts.
    ///
    /// # Errors
    /// Refuses missing installing Source. This split creates no owner, clock or
    /// permission; the lender's original checks remain independent of the view.
    #[cfg(not(test))]
    pub(crate) fn mapped_region_with_installer(
        &mut self,
    ) -> Result<
        (
            &mut MappedSetupView,
            &crate::startup_source::InstallerStartupSource,
        ),
        crate::StartupSourceError,
    > {
        let source = self
            .startup_source
            .as_ref()
            .ok_or(crate::StartupSourceError::Ownership {
                reason: "initial installer Source is absent",
            })?;
        Ok((self.mapped_region.view_mut(), source))
    }

    // Source's authentic creator already fixes permanent DONTFORK. Parent
    // barrier release corroborates that same owner without undoing disposition.
    pub(crate) fn exclude_setup_mapping_from_child(&self) -> Result<(), i32> {
        self.mapped_region
            .exclude_from_child(self.startup_source.as_ref())
    }

    pub(crate) fn restore_setup_mapping_parent(&self) -> Result<(), i32> {
        self.mapped_region
            .restore_parent(self.startup_source.as_ref())
    }

    /// Moves genuine creation custody after completion enrollment on pinned Runtime.
    ///
    /// # Safety
    /// Runtime and its canonical destination must remain pinned through Native return.
    ///
    /// # Errors
    /// Preserves the authentic installing or transfer refusal and every born field.
    pub(crate) unsafe fn transfer_setup_mapping(&self) -> Result<(), crate::StartupSourceError> {
        // SAFETY: the only production caller retains the pinned Runtime before
        // completion enrollment and cannot move it after this canonical transfer.
        unsafe { self.original_startup()?.transfer_setup_mapping() }
    }

    /// Returns the mapping only after the retained Runtime's last users close.
    ///
    /// # Safety
    /// The exclusive Runtime destructor has ended every callback, worker and
    /// detached view use. A true result forbids subsequent mapping access;
    /// refusal retains the pinned Runtime and its canonical mapping field.
    pub(crate) unsafe fn return_setup_mapping(&self) -> bool {
        match self.startup_source.as_ref() {
            // SAFETY: the caller's final-use contract is forwarded unchanged.
            Some(source) => unsafe { source.return_setup_mapping() },
            None => self.mapped_region.is_owned_fixture(),
        }
    }

    /// Returns the validated setup region header token.
    #[must_use]
    pub const fn validated_region(&self) -> ValidatedSetupRegion {
        self.validated_region
    }

    /// Returns the exact setup-time shared-memory layout contract.
    #[must_use]
    pub const fn validated_layout(&self) -> RegionLayout {
        self.validated_layout
    }

    /// Returns the backing object's stable device number captured before mmap.
    #[must_use]
    pub const fn shared_memory_device(&self) -> u64 {
        self.shared_memory_device
    }

    /// Returns the backing object's nonzero inode captured before mmap.
    #[must_use]
    pub const fn shared_memory_inode(&self) -> u64 {
        self.shared_memory_inode
    }

    /// Returns the armed wake fd token.
    #[must_use]
    pub const fn wake_fd(&self) -> &ArmedWakeFd {
        &self.wake_fd
    }

    /// Returns the validated immutable app-random branch replay plan.
    #[must_use]
    pub const fn app_random_branch_plan(&self) -> &AppRandomBranchPlan {
        &self.app_random_branch_plan
    }

    /// Returns the v4 catalog plan until the live callback owner takes it.
    #[must_use]
    pub const fn selectable_catalog_plan(&self) -> Option<&SelectableCatalogPlan> {
        self.selectable_catalog_plan.as_ref()
    }

    /// Transfers the validated catalog plan into the pinned live callback owner.
    pub(crate) fn take_selectable_catalog_plan(&mut self) -> Option<SelectableCatalogPlan> {
        self.selectable_catalog_plan.take()
    }

    /// Returns evidence that the wake fd was registered with QEMU.
    #[must_use]
    pub const fn registered_wake_fd(&self) -> Option<RegisteredWakeFd> {
        self.registered_wake_fd
    }
}

/// Typed evidence that the ready `SetupAck(0)` was sent.
#[derive(Debug)]
pub struct PluginReadySetupAck {
    _private: (),
}

impl PluginReadySetupAck {
    const fn acknowledged(_owned_callbacks: &RequiredOwnedCallbacksRegistered) -> Self {
        Self { _private: () }
    }

    #[cfg(test)]
    pub(crate) const fn test_acknowledged() -> Self {
        Self { _private: () }
    }
}

/// Receives the setup frame and its three or four fixed-order descriptors.
///
/// # Errors
///
/// Returns [`PluginSetupError::ReceiveSetup`] when the control socket does not
/// carry a valid `Setup` frame with the required three or four `SCM_RIGHTS` descriptors, or
/// [`PluginSetupError::SendFailureAck`] when that setup failure cannot be
/// acknowledged.
#[cfg(all(test, unix))]
pub fn receive_setup_with_descriptors<S>(stream: &mut S) -> Result<ReceivedSetup, PluginSetupError>
where
    S: AsRawFd + Write,
{
    match recv_setup_with_descriptors(stream.as_raw_fd()) {
        Ok(setup) => Ok(setup),
        Err(source) => {
            send_setup_failure_ack(stream, PluginSetupFailureStage::ReceiveSetup)?;
            Err(PluginSetupError::ReceiveSetup { source })
        }
    }
}

/// Receives and prepares setup using the negotiated handshake assignment.
///
/// # Errors
///
/// Returns [`PluginSetupError`] when descriptor handover, mapping, header
/// validation, handshake/header cross-checking, wake-fd arming, or failure
/// acknowledgement fails.
#[cfg(all(test, unix))]
pub fn receive_and_prepare_setup_completion<S>(
    stream: &mut S,
    handshake: PluginControlHandshake,
) -> Result<PluginSetupCompletion, PluginSetupError>
where
    S: AsRawFd + Write,
{
    let setup = receive_setup_with_descriptors(stream)?;
    prepare_setup_completion(stream, setup, handshake)
}

/// Prepares plugin setup completion before callback registration and ready ack.
///
/// On success, this function has mapped the shared-memory descriptor for
/// exactly `Setup.region_len`, validated the shmem ABI marker and geometry, and
/// armed the wake fd after cross-checking the mapped region against the
/// negotiated handshake assignment. It intentionally defers QEMU wake-fd
/// registration and does not send `SetupAck(0)`; callers must first prove plugin
/// callback ownership, register the wake fd, and then call [`send_ready_setup_ack`].
/// On setup failure before callback registration, it
/// attempts to send a nonzero `SetupAck` before returning the setup error.
///
/// # Errors
///
/// Returns [`PluginSetupError`] when mapping, validation, handshake/header slot
/// consistency, wake-fd arming, or failure-acknowledgement I/O fails.
#[cfg(all(test, unix))]
pub fn prepare_setup_completion<W>(
    writer: &mut W,
    setup: ReceivedSetup,
    handshake: PluginControlHandshake,
) -> Result<PluginSetupCompletion, PluginSetupError>
where
    W: Write,
{
    let (input, plan) = separate_received_plan(setup);
    prepare_setup_completion_borrowing_plan(writer, input, plan.as_fd(), None, handshake)
}

/// Received setup resources with the independently retained third owner removed.
#[cfg(unix)]
pub(crate) struct SetupPreparationInput {
    region_len: u64,
    process_generation: u64,
    shmem_fd: crate::startup_source::SetupDescriptor,
    wake_fd: crate::startup_source::SetupDescriptor,
    workspace_binding: Option<crucible_qemu_protocol::DeviceDigestWorkspaceBinding>,
    workspace_fd: Option<crate::startup_source::SetupDescriptor>,
}

#[cfg(all(test, unix))]
pub(crate) fn separate_received_plan(setup: ReceivedSetup) -> (SetupPreparationInput, OwnedFd) {
    (
        SetupPreparationInput {
            region_len: setup.region_len,
            process_generation: setup.process_generation,
            shmem_fd: setup.descriptors.shmem_fd.into(),
            wake_fd: setup.descriptors.wake_fd.into(),
            workspace_binding: setup.device_digest_workspace,
            workspace_fd: setup.descriptors.device_digest_workspace.map(Into::into),
        },
        setup.descriptors.plugin_setup_plan_fd,
    )
}

impl SetupPreparationInput {
    pub(crate) fn from_native_setup(
        setup: &crate::startup_source::NativeSetupBorrow,
    ) -> Result<Self, crate::StartupSourceError> {
        let frame = setup.frame();
        let malformed = || crate::StartupSourceError::Ownership {
            reason: "selected setup frame fields differ",
        };
        if frame[..4] != 57_u32.to_be_bytes() || frame[4] != crucible_qemu_protocol::TAG_SETUP {
            return Err(malformed());
        }
        let read_u64 =
            |offset| u64::from_be_bytes(std::array::from_fn(|index| frame[offset + index]));
        let region_len = read_u64(5);
        let process_generation = read_u64(21);
        let workspace_binding = if setup.has_workspace() {
            let binding = crucible_qemu_protocol::DeviceDigestWorkspaceBinding {
                account_generation: read_u64(29),
                workspace_generation: read_u64(37),
                device: read_u64(45),
                inode: read_u64(53),
            };
            if frame[13..17] != 1_u32.to_be_bytes()
                || frame[17..21] != 2_u32.to_be_bytes()
                || binding.account_generation == 0
                || binding.workspace_generation == 0
            {
                return Err(malformed());
            }
            Some(binding)
        } else {
            if frame[13..21] != [0; 8] || frame[29..61] != [0; 32] {
                return Err(malformed());
            }
            None
        };
        if region_len == 0 || process_generation == 0 {
            return Err(malformed());
        }
        Ok(Self {
            region_len,
            process_generation,
            shmem_fd: setup.role(0)?,
            wake_fd: setup.role(1)?,
            workspace_binding,
            workspace_fd: if setup.has_workspace() {
                Some(setup.role(5)?)
            } else {
                None
            },
        })
    }
}

// This core never acquires Source from a caller-supplied descriptor. Runtime's
// sole receive path retains the original owner outside every fallible effect.
#[cfg(unix)]
pub(crate) fn prepare_setup_completion_borrowing_plan<W: Write>(
    writer: &mut W,
    input: SetupPreparationInput,
    plugin_setup_plan_fd: BorrowedFd<'_>,
    original: Option<&crate::startup_source::InstallerStartupSource>,
    handshake: PluginControlHandshake,
) -> Result<PluginSetupCompletion, PluginSetupError> {
    let SetupPreparationInput {
        region_len,
        process_generation,
        shmem_fd,
        wake_fd,
        workspace_binding,
        workspace_fd,
    } = input;
    let device_digest_workspace = match (workspace_binding, workspace_fd) {
        (Some(binding), Some(descriptor)) => Some((binding, descriptor)),
        (None, None) => None,
        _ => {
            send_setup_failure_ack(writer, PluginSetupFailureStage::ReceiveSetup)?;
            return Err(PluginSetupError::DeviceDigestWorkspacePresence);
        }
    };
    if let Some(original) = original {
        original
            .check()
            .map_err(|source| PluginSetupError::StartupSource { source })?;
    }

    let (shared_memory_device, shared_memory_inode) = match shared_memory_identity(shmem_fd.as_fd())
    {
        Ok(identity) => identity,
        Err(errno) => {
            send_setup_failure_ack(writer, PluginSetupFailureStage::MapRegion)?;
            return Err(PluginSetupError::InspectSharedMemory { errno });
        }
    };

    let decoded_plans = match read_plugin_setup_plan(
        plugin_setup_plan_fd,
        original.and_then(crate::startup_source::InstallerStartupSource::retained_native_setup),
    ) {
        Ok(plans) => plans,
        Err(source) => {
            send_setup_failure_ack(writer, PluginSetupFailureStage::ValidatePluginSetupPlan)?;
            return Err(PluginSetupError::ValidatePluginSetupPlan { source });
        }
    };

    if let Some(original) = original {
        original
            .check()
            .map_err(|source| PluginSetupError::StartupSource { source })?;
    }

    // Production consumes the genuine Source-created VMA. The wire view owns
    // no mapping and the original Source remains retained across every refusal.
    let mapped_region = match mapping::prepare(original, shmem_fd.as_fd(), region_len) {
        Ok(mapped_region) => mapped_region,
        Err(source) => {
            send_setup_failure_ack(writer, PluginSetupFailureStage::MapRegion)?;
            return Err(source);
        }
    };

    let header_snapshot = PluginShmemOrdering::setup_header_snapshot(mapped_region.view());
    let validated_region = match PluginShmemOrdering::validate_setup_header(mapped_region.view()) {
        Ok(validated_region) => validated_region,
        Err(source) => {
            send_setup_failure_ack(writer, PluginSetupFailureStage::ValidateRegion)?;
            return Err(PluginSetupError::ValidateRegion { source });
        }
    };
    let validated_layout = match mapped_region.view().layout() {
        Ok(layout) => layout,
        Err(source) => {
            send_setup_failure_ack(writer, PluginSetupFailureStage::ValidateRegion)?;
            return Err(PluginSetupError::ValidateRegion { source });
        }
    };

    validate_setup_handshake_slot(writer, handshake, header_snapshot.node_count)?;

    let wake_fd = match ArmedWakeFd::arm_role(wake_fd) {
        Ok(wake_fd) => wake_fd,
        Err(source) => {
            send_setup_failure_ack(writer, PluginSetupFailureStage::ArmWakeFd)?;
            return Err(PluginSetupError::ArmWakeFd { source });
        }
    };
    Ok(PluginSetupCompletion {
        mapped_region,
        validated_region,
        validated_layout,
        shared_memory_device,
        shared_memory_inode,
        wake_fd,
        app_random_branch_plan: decoded_plans.app_random_branch_plan,
        selectable_catalog_plan: decoded_plans.selectable_catalog_plan,
        registered_wake_fd: None,
        process_generation,
        #[cfg(test)]
        refused_device_digest_workspace: None,
        startup_source: None,
        device_digest_workspace,
    })
}

#[cfg(unix)]
fn shared_memory_identity(fd: BorrowedFd<'_>) -> Result<(u64, u64), i32> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let status = unsafe {
        // SAFETY: `fd` is live and `metadata` points to writable stat storage.
        libc::fstat(fd.as_raw_fd(), metadata.as_mut_ptr())
    };
    if status != 0 {
        return Err(last_errno());
    }
    let metadata = unsafe {
        // SAFETY: successful fstat initialized the complete stat value.
        metadata.assume_init()
    };
    let device = metadata.st_dev;
    let inode = metadata.st_ino;
    if inode == 0 {
        return Err(libc::EINVAL);
    }
    Ok((device, inode))
}

#[cfg(unix)]
struct DecodedPluginSetupPlans {
    app_random_branch_plan: AppRandomBranchPlan,
    selectable_catalog_plan: Option<SelectableCatalogPlan>,
}

#[cfg(target_os = "linux")]
fn read_plugin_setup_plan(
    fd: BorrowedFd<'_>,
    native_setup: Option<&crate::startup_source::NativeSetupBorrow>,
) -> Result<DecodedPluginSetupPlans, PluginSetupPlanDescriptorError> {
    #[cfg(not(test))]
    if native_setup.is_none() {
        return Err(PluginSetupPlanDescriptorError::DecodeComposite {
            source: PluginSetupPlanError::InvalidPreexecSection {
                section: "native custody",
            },
        });
    }
    #[cfg(test)]
    let _model_native_custody = native_setup;
    let required_seals =
        libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL;
    let observed_seals = unsafe {
        // SAFETY: `fd` is a live descriptor received through SCM_RIGHTS and
        // F_GET_SEALS reads descriptor metadata without pointer arguments.
        libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS)
    };
    if observed_seals < 0 {
        return Err(PluginSetupPlanDescriptorError::Io {
            operation: "read plugin setup-plan seals",
            errno: last_errno(),
        });
    }
    if observed_seals & required_seals != required_seals {
        return Err(PluginSetupPlanDescriptorError::MissingSeals {
            observed: observed_seals,
            required: required_seals,
        });
    }

    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let status = unsafe {
        // SAFETY: `stat` points to writable storage for one libc::stat and the
        // received descriptor remains owned for this call.
        libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr())
    };
    if status != 0 {
        return Err(PluginSetupPlanDescriptorError::Io {
            operation: "stat plugin setup-plan descriptor",
            errno: last_errno(),
        });
    }
    let stat = unsafe {
        // SAFETY: successful fstat initialized the complete libc::stat value.
        stat.assume_init()
    };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(PluginSetupPlanDescriptorError::NotRegular);
    }
    let maximum = PLUGIN_SETUP_PLAN_MAX_BYTES;
    let length = usize::try_from(stat.st_size).map_err(|_error| {
        PluginSetupPlanDescriptorError::InvalidLength {
            bytes: usize::MAX,
            maximum,
        }
    })?;
    if length == 0 || length > maximum {
        return Err(PluginSetupPlanDescriptorError::InvalidLength {
            bytes: length,
            maximum,
        });
    }

    let mut bytes = vec![0_u8; length];
    let mut read = 0_usize;
    while read < bytes.len() {
        let offset = libc::off_t::try_from(read).map_err(|_error| {
            PluginSetupPlanDescriptorError::InvalidLength {
                bytes: length,
                maximum,
            }
        })?;
        let result = unsafe {
            // SAFETY: the destination suffix is writable for its declared
            // length and pread does not retain the pointer.
            libc::pread(
                fd.as_raw_fd(),
                bytes[read..].as_mut_ptr().cast::<libc::c_void>(),
                bytes.len() - read,
                offset,
            )
        };
        if result < 0 {
            let errno = last_errno();
            if errno == libc::EINTR {
                continue;
            }
            return Err(PluginSetupPlanDescriptorError::Io {
                operation: "read plugin setup-plan descriptor",
                errno,
            });
        }
        let count = usize::try_from(result).unwrap_or(0);
        if count == 0 {
            return Err(PluginSetupPlanDescriptorError::Truncated {
                expected: length,
                actual: read,
            });
        }
        read += count;
    }
    let (app_random_branch_plan, selectable_catalog_plan) =
        PluginSetupPlan::decode_preexec_parts(&bytes)
            .map_err(|source| PluginSetupPlanDescriptorError::DecodeComposite { source })?;
    Ok(DecodedPluginSetupPlans {
        app_random_branch_plan,
        selectable_catalog_plan: Some(selectable_catalog_plan),
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn read_plugin_setup_plan(
    _fd: BorrowedFd<'_>,
    _native_setup: Option<&crate::startup_source::NativeSetupBorrow>,
) -> Result<DecodedPluginSetupPlans, PluginSetupPlanDescriptorError> {
    Err(PluginSetupPlanDescriptorError::UnsupportedPlatform)
}

#[cfg(unix)]
fn validate_setup_handshake_slot<W>(
    writer: &mut W,
    handshake: PluginControlHandshake,
    region_node_count: u32,
) -> Result<(), PluginSetupError>
where
    W: Write,
{
    if handshake.node_count() != region_node_count {
        send_setup_failure_ack(writer, PluginSetupFailureStage::CrossCheckSlot)?;
        return Err(PluginSetupError::NodeCountMismatch {
            handshake_node_count: handshake.node_count(),
            region_node_count,
        });
    }

    if handshake.slot_index() >= region_node_count {
        send_setup_failure_ack(writer, PluginSetupFailureStage::CrossCheckSlot)?;
        return Err(PluginSetupError::SlotOutsideRegionNodeCount {
            slot_index: handshake.slot_index(),
            region_node_count,
        });
    }

    Ok(())
}

/// Sends `SetupAck(0)` after setup preparation and callback registration.
///
/// # Errors
///
/// Returns [`PluginSetupError::SendReadyAck`] when the ready acknowledgement
/// cannot be written and flushed.
#[cfg(unix)]
pub fn send_ready_setup_ack<W>(
    writer: &mut W,
    _callbacks: &PluginCallbackCapabilities,
    owned_callbacks: &RequiredOwnedCallbacksRegistered,
) -> Result<PluginReadySetupAck, PluginSetupError>
where
    W: Write,
{
    if owned_callbacks.setup().registered_wake_fd.is_none() {
        send_setup_failure_ack(writer, PluginSetupFailureStage::RegisterWakeFd)?;
        return Err(PluginSetupError::WakeFdNotRegistered);
    }
    plugin_send_setup_ack(writer, SETUP_ACK_STATUS_READY)
        .map_err(|source| PluginSetupError::SendReadyAck { source })?;
    Ok(PluginReadySetupAck::acknowledged(owned_callbacks))
}

#[cfg(unix)]
fn send_setup_failure_ack<W>(
    writer: &mut W,
    stage: PluginSetupFailureStage,
) -> Result<(), PluginSetupError>
where
    W: Write,
{
    plugin_send_setup_ack(writer, SETUP_ACK_STATUS_SETUP_FAILED)
        .map_err(|source| PluginSetupError::SendFailureAck { stage, source })
}

#[cfg(unix)]
fn set_close_on_exec(fd: RawFd) -> Result<(), WakeFdArmError> {
    // SAFETY: `fd` comes from an owned setup wake descriptor borrowed by
    // `ArmedWakeFd::arm`; `fcntl(F_GETFD)` reads descriptor flags only.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(WakeFdArmError::Fcntl {
            operation: "read wake fd descriptor flags",
            errno: last_errno(),
        });
    }

    // SAFETY: `fd` is the same live owned setup wake descriptor, and
    // `fcntl(F_SETFD)` updates only descriptor flags.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if result < 0 {
        return Err(WakeFdArmError::Fcntl {
            operation: "mark wake fd close-on-exec",
            errno: last_errno(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn set_nonblocking(fd: RawFd) -> Result<(), WakeFdArmError> {
    // SAFETY: `fd` comes from an owned setup wake descriptor borrowed by
    // `ArmedWakeFd::arm`; `fcntl(F_GETFL)` reads descriptor status flags only.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(WakeFdArmError::Fcntl {
            operation: "read wake fd status flags",
            errno: last_errno(),
        });
    }

    // SAFETY: `fd` is the same live owned setup wake descriptor, and
    // `fcntl(F_SETFL)` updates only descriptor status flags.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if result < 0 {
        return Err(WakeFdArmError::Fcntl {
            operation: "mark wake fd nonblocking",
            errno: last_errno(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn validate_wake_descriptor(fd: RawFd) -> Result<(), WakeFdArmError> {
    validate_empty_wake_descriptor(fd)?;
    #[cfg(target_os = "linux")]
    validate_eventfd_counter_semantics(fd)?;
    Ok(())
}

#[cfg(unix)]
fn validate_empty_wake_descriptor(fd: RawFd) -> Result<(), WakeFdArmError> {
    let mut value = 0_u64;
    loop {
        // SAFETY: `value` is writable for eight bytes and `fd` is owned by the
        // caller. Nonblocking mode guarantees this validation cannot park.
        let result = unsafe {
            libc::read(
                fd,
                (&mut value as *mut u64).cast::<libc::c_void>(),
                core::mem::size_of::<u64>(),
            )
        };
        if result > 0 {
            return Err(WakeFdArmError::NotEmpty {
                bytes_read: result as usize,
            });
        }
        if result == 0 {
            return Err(WakeFdArmError::EndOfFile);
        }
        let errno = last_errno();
        if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
            return Ok(());
        }
        if errno == libc::EINTR {
            continue;
        }
        return Err(WakeFdArmError::Read { errno });
    }
}

#[cfg(target_os = "linux")]
fn validate_eventfd_counter_semantics(fd: RawFd) -> Result<(), WakeFdArmError> {
    write_eventfd_probe(fd, 1)?;
    write_eventfd_probe(fd, 2)?;

    let mut observed = 0_u64;
    let bytes_read = loop {
        // SAFETY: `observed` is writable for the exact eventfd counter width and
        // `fd` remains owned by the caller for this validation.
        let result = unsafe {
            libc::read(
                fd,
                (&mut observed as *mut u64).cast::<libc::c_void>(),
                core::mem::size_of::<u64>(),
            )
        };
        if result >= 0 {
            break result as usize;
        }
        let errno = last_errno();
        if errno != libc::EINTR {
            return Err(WakeFdArmError::EventFdProbeRead { errno });
        }
    };
    if bytes_read != core::mem::size_of::<u64>() || observed != 3 {
        return Err(WakeFdArmError::EventFdCounterSemantics {
            bytes_read,
            observed,
        });
    }
    validate_empty_wake_descriptor(fd)
}

#[cfg(target_os = "linux")]
fn write_eventfd_probe(fd: RawFd, value: u64) -> Result<(), WakeFdArmError> {
    loop {
        // SAFETY: `value` is readable for the exact eventfd counter width and
        // `fd` remains owned by the caller for this validation.
        let result = unsafe {
            libc::write(
                fd,
                (&value as *const u64).cast::<libc::c_void>(),
                core::mem::size_of::<u64>(),
            )
        };
        if result == core::mem::size_of::<u64>() as isize {
            return Ok(());
        }
        if result >= 0 {
            return Err(WakeFdArmError::EventFdProbeWriteSize {
                bytes_written: result as usize,
            });
        }
        let errno = last_errno();
        if errno != libc::EINTR {
            return Err(WakeFdArmError::EventFdProbeWrite { errno });
        }
    }
}

#[cfg(unix)]
fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn test_plugin_setup_plan_fd() -> OwnedFd {
    let selectable = SelectableCatalogPlan::new(
        crucible_qemu_protocol::selectable_catalog_plan::SelectablePlanLimits::new(1, 1, 1)
            .unwrap_or_else(|error| panic!("test selectable limits must validate: {error}")),
        Vec::new(),
        crucible_qemu_protocol::selectable_catalog_plan::SelectablePlanContinuation::cold(),
    )
    .unwrap_or_else(|error| panic!("test selectable plan must validate: {error}"));
    // This private fixture assembles structurally matching bytes. Its model
    // table supplies no native issuer and cannot qualify a shipped launch.
    let startup = crucible_qemu_protocol::plugin_setup_plan::StartupOperation::new(
        crucible_qemu_protocol::plugin_setup_plan::StartupOperationFields {
            cap_id: [7; 32],
            operation_id: 2,
            original_start_ns: 1,
            absolute_end_ns: 3,
            poll_ns: 1,
            process_generation: 1,
            cancellation_device: 1,
            cancellation_inode: 2,
            cancellation_event_id: 3,
            cancellation_descriptor: 10,
            original_total_metadata_bytes: 4096,
        },
    )
    .unwrap();
    let mut purpose = [0; crucible_qemu_protocol::plugin_setup_plan::PROCESS_PURPOSE_BYTES];
    purpose[..8].copy_from_slice(b"CRUCPUR8");
    purpose[8..12].copy_from_slice(&8_u32.to_be_bytes());
    purpose[12..16].copy_from_slice(
        &(crucible_qemu_protocol::plugin_setup_plan::PROCESS_PURPOSE_BYTES as u32).to_be_bytes(),
    );
    purpose[16..24].copy_from_slice(&4096_u64.to_be_bytes());
    purpose[96..104].copy_from_slice(&1_u64.to_be_bytes());
    purpose[184..216].copy_from_slice(&[7; 32]);
    for (offset, value) in [
        (512, 1_u64),
        (520, 2),
        (528, 100_000),
        (536, 100_000),
        (544, 64),
        (552, 3001),
        (560, 3001),
    ] {
        purpose[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    // Syntax-only reservations exercise the codec; they issue no native owner.
    for (offset, value) in [
        (24, 2048_u64),
        (72, 512),
        (80, 1),
        (88, 9),
        (104, 1024),
        (112, 256),
        (120, 1),
        (128, 32),
        (136, 1),
        (472, 1024),
        (480, 2),
        (528, 100_000),
    ] {
        purpose[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    let mut family = [0; 256];
    family[..8].copy_from_slice(b"CRUCFAM1");
    family[8..12].copy_from_slice(&1_u32.to_be_bytes());
    family[12..16].copy_from_slice(&256_u32.to_be_bytes());
    family[16..48].copy_from_slice(&purpose[184..216]);
    family[48..56].copy_from_slice(&9_u64.to_be_bytes());
    family[56..64].copy_from_slice(&9_u64.to_be_bytes());
    for (index, identity) in [(0, 11), (1, 13)] {
        let offset = 64 + index * 96;
        family[offset..offset + 4].copy_from_slice(&(index as u32).to_be_bytes());
        family[offset + 8..offset + 40].fill(identity);
        for (relative, value) in [
            (40, 1024_u64),
            (56, 1024),
            (64, 256),
            (72, 1),
            (80, 32),
            (88, 1),
        ] {
            family[offset + relative..offset + relative + 8].copy_from_slice(&value.to_be_bytes());
        }
    }
    purpose[744..1000].copy_from_slice(&family);
    // Fixed syntax-only standing observation; no kernel owner is issued.
    for (offset, value) in [(1000, 1_u64), (1008, 29), (1016, 1504)] {
        purpose[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    let mut standing = [0_u8; 1496];
    standing[..8].copy_from_slice(b"CRUCSRV4");
    standing[8..12].copy_from_slice(&4_u32.to_be_bytes());
    standing[12..16].copy_from_slice(&1496_u32.to_be_bytes());
    standing[16..48].copy_from_slice(&purpose[184..216]);
    standing[88..120].copy_from_slice(&purpose[184..216]);
    standing[120..152].copy_from_slice(&purpose[816..848]);
    standing[200..232].copy_from_slice(&purpose[144..176]);
    standing[72..80].copy_from_slice(&purpose[88..96]);
    standing[80..88].copy_from_slice(&purpose[96..104]);
    for (offset, value) in [(48, 1_u64), (160, 1), (168, 2), (176, 1)] {
        standing[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    // Independently authored schema11 literal roster: fourteen 1ns polls,
    // absent progress and 500us total bounds, with canonical zero padding.
    standing[192..196].copy_from_slice(&256_u32.to_be_bytes());
    standing[196..200].copy_from_slice(&1_u32.to_be_bytes());
    standing[232..236].copy_from_slice(&11_u32.to_be_bytes());
    for index in 0..14 {
        let offset = 236 + index * 18;
        standing[offset..offset + 8].copy_from_slice(&1_u64.to_be_bytes());
        standing[offset + 9] = 1;
        standing[offset + 10..offset + 18].copy_from_slice(&500_000_u64.to_be_bytes());
    }
    purpose[1024..2520].copy_from_slice(&standing);

    let bytes = PluginSetupPlan::new(AppRandomBranchPlan::default(), selectable)
        .with_startup_operation(startup)
        .encode_preexec(&purpose, None)
        .unwrap();
    test_sealed_setup_plan_fd(&bytes)
}

#[cfg(all(test, target_os = "linux"))]
fn test_sealed_setup_plan_fd(bytes: &[u8]) -> OwnedFd {
    use std::os::fd::FromRawFd;

    let name = c"crucible-test-plugin-setup-plan";
    let raw_fd = unsafe {
        // SAFETY: the C string is static and memfd_create returns a new fd.
        libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
    };
    assert!(raw_fd >= 0, "test branch-plan memfd should be created");
    let fd = unsafe {
        // SAFETY: successful memfd_create returned a uniquely owned fd.
        OwnedFd::from_raw_fd(raw_fd)
    };
    let length = libc::off_t::try_from(bytes.len())
        .unwrap_or_else(|error| panic!("test plan length should fit off_t: {error}"));
    let truncate = unsafe {
        // SAFETY: `fd` is live and `length` is range checked.
        libc::ftruncate(fd.as_raw_fd(), length)
    };
    assert_eq!(truncate, 0, "test branch-plan memfd should size");
    let written = unsafe {
        // SAFETY: `bytes` is readable for its complete length and pwrite does
        // not retain the pointer.
        libc::pwrite(
            fd.as_raw_fd(),
            bytes.as_ptr().cast::<libc::c_void>(),
            bytes.len(),
            0,
        )
    };
    assert_eq!(written, bytes.len() as isize, "test plan should write");
    let seals = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL;
    let sealed = unsafe {
        // SAFETY: `fd` is a live sealable memfd.
        libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals)
    };
    assert_eq!(sealed, 0, "test branch-plan memfd should seal");
    fd
}

/// An error produced while arming the setup wake fd.
#[cfg(unix)]
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WakeFdArmError {
    /// A descriptor flag syscall failed.
    #[error("{operation} failed with errno {errno}")]
    Fcntl {
        /// The operation being attempted.
        operation: &'static str,
        /// Raw OS errno value.
        errno: i32,
    },
    /// The descriptor already contained a wake value.
    #[error("wake fd was not empty; read {bytes_read} pending bytes")]
    NotEmpty {
        /// Bytes consumed while detecting the invalid pending wake.
        bytes_read: usize,
    },
    /// The descriptor reports permanent EOF instead of an empty wake queue.
    #[error("wake fd reports end-of-file instead of an empty wake queue")]
    EndOfFile,
    /// Reading the nonblocking descriptor failed unexpectedly.
    #[error("validating empty wake fd failed with errno {errno}")]
    Read {
        /// Raw OS errno value.
        errno: i32,
    },
    /// Writing a Linux eventfd counter probe failed.
    #[error("writing eventfd counter probe failed with errno {errno}")]
    EventFdProbeWrite {
        /// Raw OS errno value.
        errno: i32,
    },
    /// A Linux eventfd counter probe produced a short write.
    #[error("eventfd counter probe wrote {bytes_written} bytes instead of 8")]
    EventFdProbeWriteSize {
        /// Number of bytes accepted by the descriptor.
        bytes_written: usize,
    },
    /// Reading a Linux eventfd counter probe failed.
    #[error("reading eventfd counter probe failed with errno {errno}")]
    EventFdProbeRead {
        /// Raw OS errno value.
        errno: i32,
    },
    /// The descriptor did not aggregate two writes like a non-semaphore eventfd.
    #[error(
        "wake descriptor lacks eventfd counter semantics: read {bytes_read} bytes with value {observed}"
    )]
    EventFdCounterSemantics {
        /// Number of bytes returned by the counter read.
        bytes_read: usize,
        /// Counter value returned after writing one and two.
        observed: u64,
    },
}

/// An error produced while registering the armed wake fd with QEMU.
#[cfg(unix)]
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WakeFdRegisterError {
    /// The descriptor was already registered for this setup completion.
    #[error("QEMU wake fd was already registered")]
    AlreadyRegistered,
    /// QEMU rejected the descriptor.
    #[error("QEMU wake-fd registration rejected descriptor with status {status}")]
    Rejected {
        /// Raw QEMU status code.
        status: i32,
    },
}

/// Error produced while waking QEMU for plugin teardown.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WakeFdSignalError {
    /// The teardown eventfd write failed.
    #[error("signaling teardown wake fd failed with errno {errno}")]
    Write {
        /// OS error code returned by `write`.
        errno: i32,
    },
    /// The eventfd accepted only part of its fixed-width counter.
    #[error("teardown wake fd wrote {bytes_written} bytes instead of 8")]
    ShortWrite {
        /// Nonnegative short byte count returned by `write`.
        bytes_written: isize,
    },
}

/// An error produced while completing plugin setup.
#[cfg(unix)]
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PluginSetupError {
    /// The original installing invocation refused before setup effects.
    #[error("original startup Source refused: {source}")]
    StartupSource {
        /// Fixed native status or unavailable entry point; no formatted wrapper.
        source: crate::StartupSourceError,
    },
    /// The workspace binding and descriptor presence disagree.
    #[error("setup workspace binding and descriptor presence disagree")]
    DeviceDigestWorkspacePresence,
    /// Receiving the setup frame and descriptors failed.
    #[error("receiving setup descriptors failed")]
    ReceiveSetup {
        /// Underlying descriptor-handover error.
        source: DescriptorHandoverError,
    },
    /// Inspecting the shared-memory backing identity failed.
    #[error("inspecting setup shared-memory identity failed with errno {errno}")]
    InspectSharedMemory {
        /// Raw operating-system errno, or EINVAL for a zero inode.
        errno: i32,
    },
    /// Mapping the setup shared-memory descriptor failed.
    #[error("setup shared-memory mmap failed")]
    MapRegion {
        /// Underlying mapping error.
        source: SetupRegionMapError,
    },
    /// Validating the mapped region header failed.
    #[error("setup shared-memory validation failed")]
    ValidateRegion {
        /// Underlying validation error.
        source: RegionSetupValidationError,
    },
    /// Validating the immutable current-version setup-plan descriptor failed.
    #[error("setup plugin-plan validation failed")]
    ValidatePluginSetupPlan {
        /// Underlying descriptor or canonical-plan failure.
        source: PluginSetupPlanDescriptorError,
    },
    /// The handshake node count disagrees with the mapped shared-memory header.
    #[error(
        "setup node_count mismatch: handshake {handshake_node_count}, region {region_node_count}"
    )]
    NodeCountMismatch {
        /// Node count accepted during `Hello`/`HelloAck`.
        handshake_node_count: u32,
        /// Node count read from the mapped region header.
        region_node_count: u32,
    },
    /// The negotiated slot does not fit in the mapped shared-memory region.
    #[error("handshake slot {slot_index} is outside setup region node_count {region_node_count}")]
    SlotOutsideRegionNodeCount {
        /// Slot accepted during `Hello`/`HelloAck`.
        slot_index: u32,
        /// Node count read from the mapped region header.
        region_node_count: u32,
    },
    /// Arming the setup wake fd failed.
    #[error("setup wake fd arming failed")]
    ArmWakeFd {
        /// Underlying wake-fd arming error.
        source: WakeFdArmError,
    },
    /// Registering the setup wake fd with QEMU failed.
    #[error("setup wake fd registration failed")]
    RegisterWakeFd {
        /// Underlying wake-fd registration error.
        source: WakeFdRegisterError,
    },
    /// Ready acknowledgement was attempted before QEMU wake registration.
    #[error("setup wake fd is not registered with QEMU")]
    WakeFdNotRegistered,
    /// The ready `SetupAck(0)` could not be sent.
    #[error("sending ready SetupAck failed")]
    SendReadyAck {
        /// Underlying frame I/O error.
        source: SetupCompletionError,
    },
    /// The failure `SetupAck(nonzero)` could not be sent.
    #[error("sending failure SetupAck failed after {stage:?}")]
    SendFailureAck {
        /// Setup stage whose failure could not be acknowledged.
        stage: PluginSetupFailureStage,
        /// Underlying frame I/O error.
        source: SetupCompletionError,
    },
}

/// Invalid immutable descriptor carrying the current-version plugin plan.
#[cfg(unix)]
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PluginSetupPlanDescriptorError {
    /// Descriptor metadata or content I/O failed.
    #[error("{operation} failed with errno {errno}")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Raw OS errno.
        errno: i32,
    },
    /// The descriptor was not a regular memfd-like file.
    #[error("plugin setup-plan descriptor is not a regular file")]
    NotRegular,
    /// The descriptor did not carry every immutability seal.
    #[error("plugin setup-plan seals {observed:#x} do not include {required:#x}")]
    MissingSeals {
        /// Observed seal mask.
        observed: i32,
        /// Required seal mask.
        required: i32,
    },
    /// The descriptor length was empty, unrepresentable, or oversized.
    #[error("plugin setup-plan descriptor has {bytes} bytes, maximum {maximum}")]
    InvalidLength {
        /// Actual or overflow-saturated byte count.
        bytes: usize,
        /// Maximum admitted byte count.
        maximum: usize,
    },
    /// The descriptor ended before its statted length.
    #[error("plugin setup-plan descriptor ended at {actual} bytes, expected {expected}")]
    Truncated {
        /// Statted byte length.
        expected: usize,
        /// Bytes read before EOF.
        actual: usize,
    },
    /// The v3 descriptor body was not a canonical composite plugin plan.
    #[error("v3 composite plugin setup-plan body is invalid: {source}")]
    DecodeComposite {
        /// Canonical composite-plan failure.
        source: PluginSetupPlanError,
    },
    /// Immutable plan descriptors are not implemented on this platform.
    #[error("plugin setup-plan descriptors require Linux memfd seals")]
    UnsupportedPlatform,
}

#[cfg(all(test, unix))]
mod tests;
