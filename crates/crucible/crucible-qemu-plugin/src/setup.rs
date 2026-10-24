//! Setup completion for the QEMU plugin control protocol.
//!
//! The setup path consumes the `Setup` descriptors, maps the shared-memory
//! region for exactly the advertised byte length, validates the region header,
//! authenticates the current-version sealed plugin plan, and arms the wake
//! fd for later event-loop registration. The caller then proves plugin callback
//! ownership, registers the wake fd, and sends `SetupAck(0)` with the returned
//! completion token. Descriptor validity comes from the fixed SCM_RIGHTS
//! handoff; mmap lifetime is owned by the returned [`PluginSetupCompletion`]
//! token.

#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};

use thiserror::Error;

#[cfg(unix)]
use crucible_qemu_protocol::{
    DescriptorHandoverError, ReceivedSetup, SETUP_ACK_STATUS_READY, SETUP_ACK_STATUS_SETUP_FAILED,
    SetupCompletionError,
    app_random_branch_plan::AppRandomBranchPlan,
    plugin_send_setup_ack,
    plugin_setup_plan::{PLUGIN_SETUP_PLAN_MAX_BYTES, PluginSetupPlan, PluginSetupPlanError},
    recv_setup_with_descriptors,
    selectable_catalog_plan::SelectableCatalogPlan,
};
#[cfg(unix)]
use crucible_qemu_shmem::{
    HotForkChildMappingInstallError, MappedSetupRegion, RegionLayout, RegionSetupValidationError,
    RetainedWholeMapping, SetupRegionBackingIdentity, SetupRegionMapError, SharedOwnedSetupMapping,
    SharedSetupMappingReadGuard, ValidatedSetupRegion, WholeMappingCustodyError, mmap_setup_region,
};

#[cfg(unix)]
use crate::{
    PluginCallbackCapabilities, PluginControlHandshake, QemuRegisterWakeFdFn,
    RequiredOwnedCallbacksRegistered, shmem_ordering::PluginShmemOrdering,
};

#[cfg(unix)]
mod boot_barrier;
#[cfg(unix)]
mod whole_setup;
#[cfg(unix)]
pub use boot_barrier::PluginSetupBootBarrierError;
#[cfg(unix)]
pub(crate) use whole_setup::prepare_selected_setup_completion;
#[cfg(unix)]
mod failure_ack;
#[cfg(unix)]
pub use failure_ack::{PluginSetupFailureStage, send_callback_registration_failure_ack};

/// An eventfd descriptor armed for setup-complete wake handling.
#[cfg(unix)]
#[derive(Debug)]
pub struct ArmedWakeFd {
    fd: WakeDescriptorCustody,
}

#[cfg(unix)]
#[derive(Debug)]
enum WakeDescriptorCustody {
    Ordinary(OwnedFd),
    Selected {
        raw: RawFd,
        _original_socket:
            std::sync::Arc<crate::runtime::whole_original_socket::OriginalWholeSocket>,
    },
}

#[cfg(unix)]
impl WakeDescriptorCustody {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::Ordinary(fd) => fd.as_raw_fd(),
            Self::Selected { raw, .. } => *raw,
        }
    }
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
        Ok(Self {
            fd: WakeDescriptorCustody::Ordinary(fd),
        })
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
    mapped_region: SharedOwnedSetupMapping,
    original_mapping_geometry: (usize, u64),
    validated_region: ValidatedSetupRegion,
    validated_layout: RegionLayout,
    shared_memory_device: u64,
    shared_memory_inode: u64,
    wake_fd: ArmedWakeFd,
    app_random_branch_plan: AppRandomBranchPlan,
    selectable_catalog_plan: Option<SelectableCatalogPlan>,
    whole_constructor:
        Option<crucible_qemu_protocol::whole_control::staged::selection::WholeConstructorSelection>,
    original_setup_body: Box<[u8]>,
    original_setup_fd: whole_setup::RetainedSetupDescriptor,
    registered_wake_fd: Option<RegisteredWakeFd>,
}

#[cfg(unix)]
impl PluginSetupCompletion {
    /// Borrows the complete original sealed descriptor body retained before installation.
    #[must_use]
    pub fn original_setup_body(&self) -> &[u8] {
        &self.original_setup_body
    }

    /// Borrows the same original sealed descriptor received through setup handover.
    ///
    /// # Errors
    /// Refuses a selected descriptor outside its original process or journal.
    pub fn original_setup_fd(&self) -> Result<BorrowedFd<'_>, PluginSetupError> {
        self.original_setup_fd.borrow()
    }

    /// Borrows the explicitly selected staged constructor and all logical names.
    ///
    /// Names and encoded limits grant no physical queue or native readiness.
    #[must_use]
    pub fn whole_constructor(
        &self,
    ) -> Option<&crucible_qemu_protocol::whole_control::staged::selection::WholeConstructorSelection>
    {
        self.whole_constructor.as_ref()
    }
    /// Returns original scalar geometry without touching an absent child VMA.
    ///
    /// Native fork-plan checks use these immutable coordinates before source
    /// replacement. They grant no mapping ownership, epoch or readiness.
    pub(crate) const fn original_mapping_geometry(&self) -> (usize, u64) {
        self.original_mapping_geometry
    }

    /// Borrows the current process's original mapping under a short guard.
    ///
    /// The guard ends before returning to native code. References obtained
    /// through it cannot escape into another callback or mutable service loan.
    ///
    /// # Errors
    /// Refuses foreign, busy, poisoned or unregistered mapping ownership.
    pub fn mapped_region(
        &self,
    ) -> Result<SharedSetupMappingReadGuard<'_>, WholeMappingCustodyError> {
        self.mapped_region.mapping()
    }

    /// Borrows the initial ordinary mapping before callback registration.
    ///
    /// # Errors
    ///
    /// Refuses foreign, selected, poisoned or nonunique initial ownership.
    pub(crate) fn mapped_region_mut(
        &mut self,
    ) -> Result<&mut MappedSetupRegion, WholeMappingCustodyError> {
        self.mapped_region.ordinary_mapping_mut()
    }

    /// Borrows immutable mapping facts without retaining a guard across callbacks.
    ///
    /// The closure performs Rust observations only and does not reenter native
    /// code. Native getter calls precede this short mapping observation.
    ///
    /// # Errors
    ///
    /// Refuses foreign or unavailable current mapping ownership.
    pub(crate) fn with_mapped_region<T>(
        &self,
        read: impl FnOnce(&MappedSetupRegion) -> T,
    ) -> Result<T, WholeMappingCustodyError> {
        let mapping = self.mapped_region()?;
        Ok(read(&mapping))
    }

    /// Returns the current actual mapping identity after PID authentication.
    ///
    /// This identity may differ from the immutable setup-time identity after
    /// a genuine fork replacement. No source readiness follows from identity.
    ///
    /// # Errors
    ///
    /// Refuses foreign or unavailable current mapping ownership.
    pub(crate) fn current_backing_identity(
        &self,
    ) -> Result<SetupRegionBackingIdentity, WholeMappingCustodyError> {
        self.with_mapped_region(MappedSetupRegion::backing_identity)
    }

    /// Reserves original owning retention before native constructor effects.
    ///
    /// The issuer calls this before registering or entering native SourceHOLD.
    /// Failure stops that construction; it cannot fall back to ordinary IO.
    ///
    /// # Errors
    ///
    /// Refuses foreign, failed, busy, poisoned or exhausted original retention.
    pub(crate) fn prepare_whole_mapping_intent_retention(
        &self,
    ) -> Result<(), crucible_qemu_shmem::WholeMappingCustodyError> {
        self.mapped_region.prepare_whole_intent_retention()
    }

    /// Lends restricted original ring construction for authenticated stopped RR.
    ///
    /// Native permission must be captured before calling this method. The
    /// closure performs only Rust construction; no borrow or guard may cross a
    /// native setter, binding, HOLD or service callback. The view never exposes
    /// mutable ownership of the mapping itself or permits its replacement.
    ///
    /// # Errors
    ///
    /// Refuses foreign, unprepared, failed, selected, busy or shared ownership.
    /// Current-generation refusal retains the same prepared mapping ticket.
    pub(crate) fn with_whole_ordinary_preparation<T, E>(
        &self,
        construct: impl FnOnce(&mut crucible_qemu_shmem::OrdinaryPreparationView<'_>) -> Result<T, E>,
    ) -> Result<Result<T, E>, WholeMappingCustodyError> {
        self.mapped_region.with_ordinary_preparation(construct)
    }

    /// Holds the same six source-prepared directed headers without releasing them.
    ///
    /// The caller authenticates the distinct native HOLD getter and original
    /// status destination before entry. This short Rust loan returns only
    /// mapped ring/exclusion facts; it does not create an epoch or native grant.
    ///
    /// # Errors
    ///
    /// Refuses foreign, changed, busy, repeated or incomplete original custody.
    /// Partial failure retains the armed mapping ticket and closed alias fence.
    pub(crate) fn hold_whole_prepared_directed_rings(
        &self,
        roster: &mut crucible_qemu_shmem::PreparedDirectedRingRoster,
    ) -> Result<
        crucible_qemu_shmem::PreparedDirectedRingHoldSnapshot,
        crucible_qemu_shmem::PreparedDirectedRingHoldError,
    > {
        self.mapped_region.hold_prepared_directed_rings(roster)
    }

    /// Fences ordinary aliases before observing the real native constructor.
    ///
    /// The literal source callback establishes native HOLD first, then calls
    /// this before fallible getter observation. No Rust guard remains held
    /// when the native getter is invoked, and no readiness is inferred.
    ///
    /// # Errors
    ///
    /// Refuses foreign or unavailable ownership and existing ordinary loans.
    /// Refusal keeps the same original mapping intent-fenced.
    #[expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )]
    pub(crate) fn begin_whole_mapping_intent(&self) -> Result<(), WholeMappingCustodyError> {
        self.mapped_region.begin_whole_intent()
    }

    /// Cancels local scope custody before any native failure is returned.
    ///
    /// The mandatory native refusal callback and every getter, body or
    /// currentness failure invoke this without borrowing mapped memory or
    /// entering an ownership mutex. It preserves original HELD ownership and
    /// history; native retirement, ACK consumption and release remain absent.
    pub(crate) fn refuse_whole_mapping_control(&self) {
        self.mapped_region.refuse_whole_control();
    }

    /// Adopts the native constructor's exact original mapping and role roster.
    ///
    /// The real native getter, constructor receipt and registered handles must
    /// authenticate epoch, capacity and offsets before calling this method.
    /// Its one guard installs sticky selection and the exact restricted roster
    /// before returning; local success establishes no native readiness.
    ///
    /// # Errors
    ///
    /// Returns sticky selection or exact original-header roster refusal.
    #[expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )]
    pub(crate) fn select_whole_mapping_roster_bounded(
        &self,
        epoch: u64,
        operation_capacity: u64,
        header_offsets: &[u64],
    ) -> Result<(), WholeMappingCustodyError> {
        self.mapped_region
            .select_whole_roster_bounded(epoch, operation_capacity, header_offsets)
    }

    /// Borrows the same selected mapping for one authenticated Rust callback.
    ///
    /// Native currentness is checked before entering this short guard. The
    /// closure makes no calls back into C, and no mapping reference escapes.
    /// Separate begin and end callbacks retain only the finite TLS permit.
    ///
    /// # Errors
    ///
    /// Refuses foreign or unavailable selected custody, or retains the
    /// callback's original error without inferring native retirement.
    #[expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )]
    pub(crate) fn with_selected_whole_mapping<T, E>(
        &self,
        callback: impl FnOnce(&mut RetainedWholeMapping) -> Result<T, E>,
    ) -> Result<Result<T, E>, WholeMappingCustodyError> {
        self.mapped_region.with_selected(callback)
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

    /// Returns the immutable setup-time backing device number.
    #[must_use]
    pub const fn shared_memory_device(&self) -> u64 {
        self.shared_memory_device
    }

    /// Returns the immutable setup-time backing inode.
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

    /// Installs and revalidates one exact branch-private child mapping.
    ///
    /// The source mapping must already be absent from the fork child. The new
    /// descriptor must match the authenticated plan identity, must not alias
    /// the template source object, and must reproduce the setup-time ABI and
    /// layout contract before any retained callback pointer is used.
    ///
    /// # Errors
    ///
    /// Returns [`PluginSetupChildMappingError`] when exact mapping placement or
    /// identity authentication fails, the replacement header is invalid, or
    /// its validated setup contract differs from the template contract.
    pub(crate) fn install_hot_fork_child_mapping(
        &self,
        fd: BorrowedFd<'_>,
        expected: SetupRegionBackingIdentity,
    ) -> Result<(), PluginSetupChildMappingError> {
        self.mapped_region
            .install_hot_fork_child_mapping(fd, expected)
            .map_err(|source| PluginSetupChildMappingError::Install { source })?;

        let mapping = self
            .mapped_region()
            .map_err(|source| PluginSetupChildMappingError::MappingCustody { source })?;
        let actual_region = PluginShmemOrdering::validate_setup_header(&mapping)
            .map_err(|source| PluginSetupChildMappingError::Validate { source })?;
        let actual_layout = mapping
            .layout()
            .map_err(|source| PluginSetupChildMappingError::Validate { source })?;
        if actual_region != self.validated_region || actual_layout != self.validated_layout {
            return Err(PluginSetupChildMappingError::ContractMismatch);
        }
        Ok(())
    }
}

/// Failure to bind retained plugin callback state to a fork-child mapping.
#[cfg(unix)]
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub(crate) enum PluginSetupChildMappingError {
    /// Selected mapping custody refuses ordinary child replacement.
    #[error("fork-child setup mapping custody refused installation: {source}")]
    MappingCustody {
        /// Original selected or nonunique owner refusal.
        source: WholeMappingCustodyError,
    },
    /// Exact-address mapping or backing-identity authentication failed.
    #[error("fork-child setup mapping installation failed")]
    Install {
        /// Underlying exact mapping failure.
        source: HotForkChildMappingInstallError,
    },
    /// The replacement shared-memory header or geometry is invalid.
    #[error("fork-child setup mapping validation failed")]
    Validate {
        /// Underlying ABI or layout validation failure.
        source: RegionSetupValidationError,
    },
    /// The replacement validates but differs from the template setup contract.
    #[error("fork-child setup mapping contract differs from the template")]
    ContractMismatch,
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

/// Receives the setup frame and its three fixed-order descriptors.
///
/// # Errors
///
/// Returns [`PluginSetupError::ReceiveSetup`] when the control socket does not
/// carry a valid `Setup` frame with exactly three `SCM_RIGHTS` descriptors, or
/// [`PluginSetupError::SendFailureAck`] when that setup failure cannot be
/// acknowledged.
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
pub fn prepare_setup_completion<W>(
    writer: &mut W,
    setup: ReceivedSetup,
    handshake: PluginControlHandshake,
) -> Result<PluginSetupCompletion, PluginSetupError>
where
    W: Write,
{
    let region_len = setup.region_len;
    let shmem_fd = setup.descriptors.shmem_fd;
    let wake_fd = setup.descriptors.wake_fd;
    let plugin_setup_plan_fd = setup.descriptors.plugin_setup_plan_fd;

    let (shared_memory_device, shared_memory_inode) = match shared_memory_identity(shmem_fd.as_fd())
    {
        Ok(identity) => identity,
        Err(errno) => {
            send_setup_failure_ack(writer, PluginSetupFailureStage::MapRegion)?;
            return Err(PluginSetupError::InspectSharedMemory { errno });
        }
    };

    let decoded_plans = match read_plugin_setup_plan(plugin_setup_plan_fd) {
        Ok(plans) => plans,
        Err(source) => {
            send_setup_failure_ack(writer, PluginSetupFailureStage::ValidatePluginSetupPlan)?;
            return Err(PluginSetupError::ValidatePluginSetupPlan { source });
        }
    };

    // The mmap lifetime is carried by `MappedSetupRegion`; no raw pointer to
    // shmem escapes setup without that owner and the validated-region token.
    let mapped_region = match mmap_setup_region(shmem_fd.as_fd(), region_len) {
        Ok(mapped_region) => mapped_region,
        Err(source) => {
            send_setup_failure_ack(writer, PluginSetupFailureStage::MapRegion)?;
            return Err(PluginSetupError::MapRegion { source });
        }
    };

    let header_snapshot = PluginShmemOrdering::setup_header_snapshot(&mapped_region);
    let validated_region = match PluginShmemOrdering::validate_setup_header(&mapped_region) {
        Ok(validated_region) => validated_region,
        Err(source) => {
            send_setup_failure_ack(writer, PluginSetupFailureStage::ValidateRegion)?;
            return Err(PluginSetupError::ValidateRegion { source });
        }
    };
    let validated_layout = match mapped_region.layout() {
        Ok(layout) => layout,
        Err(source) => {
            send_setup_failure_ack(writer, PluginSetupFailureStage::ValidateRegion)?;
            return Err(PluginSetupError::ValidateRegion { source });
        }
    };

    validate_setup_handshake_slot(writer, handshake, header_snapshot.node_count)?;

    let wake_fd = match ArmedWakeFd::arm(wake_fd) {
        Ok(wake_fd) => wake_fd,
        Err(source) => {
            send_setup_failure_ack(writer, PluginSetupFailureStage::ArmWakeFd)?;
            return Err(PluginSetupError::ArmWakeFd { source });
        }
    };
    Ok(PluginSetupCompletion {
        original_mapping_geometry: (mapped_region.mapping_start(), mapped_region.region_len()),
        mapped_region: SharedOwnedSetupMapping::new(mapped_region),
        validated_region,
        validated_layout,
        shared_memory_device,
        shared_memory_inode,
        wake_fd,
        app_random_branch_plan: decoded_plans.app_random_branch_plan,
        selectable_catalog_plan: decoded_plans.selectable_catalog_plan,
        whole_constructor: decoded_plans.whole_constructor,
        original_setup_body: decoded_plans.original_setup_body,
        original_setup_fd: whole_setup::RetainedSetupDescriptor::Ordinary(
            decoded_plans.original_setup_fd,
        ),
        registered_wake_fd: None,
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
    whole_constructor:
        Option<crucible_qemu_protocol::whole_control::staged::selection::WholeConstructorSelection>,
    original_setup_body: Box<[u8]>,
    original_setup_fd: OwnedFd,
}

#[cfg(target_os = "linux")]
fn read_plugin_setup_plan(
    fd: OwnedFd,
) -> Result<DecodedPluginSetupPlans, PluginSetupPlanDescriptorError> {
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
    let plan = PluginSetupPlan::decode(&bytes)
        .map_err(|source| PluginSetupPlanDescriptorError::DecodeComposite { source })?;
    let (app_random_branch_plan, selectable_catalog_plan, whole_constructor) = plan.into_parts();
    Ok(DecodedPluginSetupPlans {
        app_random_branch_plan,
        selectable_catalog_plan: Some(selectable_catalog_plan),
        whole_constructor,
        original_setup_body: bytes.into_boxed_slice(),
        original_setup_fd: fd,
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn read_plugin_setup_plan(
    _fd: OwnedFd,
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
    let bytes = PluginSetupPlan::new(AppRandomBranchPlan::default(), selectable)
        .encode()
        .unwrap_or_else(|error| panic!("test plugin setup plan must encode: {error}"));
    test_sealed_setup_plan_fd(&bytes)
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn test_sealed_setup_plan_fd(bytes: &[u8]) -> OwnedFd {
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
    /// The selected original socket/SCM journal cannot lend its original FD.
    #[error("selected original setup descriptor custody is unavailable")]
    SelectedDescriptorUnavailable,
    /// The source refused the same early descriptor at late installation.
    #[error("native source refused original selected setup with status {status}")]
    SelectedNativeAuthentication {
        /// Original native rejection status.
        status: i32,
    },

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
