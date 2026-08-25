//! Live QEMU adapters for the optional per-architecture white-box doorbell.
//!
//! The adapter recognizes the single-source x86_64 `out 0xe7,al` or aarch64
//! `hint #0x4c` encoding during translation and installs an execution callback
//! only on that dedicated instruction. The admitted path reads the architecture's
//! `(pointer, length)` payload registers and delegates bounded frame decoding to
//! [`crate::PluginWhiteboxDoorbell`]. Control-protocol v3 additionally installs
//! a policy-free selectable catalog that reconciles setup registrations,
//! freezes before readiness publication, and retains a VMStop-bound request.

use std::ffi::CStr;
use std::os::raw::{c_int, c_uint, c_void};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicPtr, Ordering};

use crucible_shmem::MAX_FRAME_DATA;

use crate::{
    GuestMemoryAddressSpace, GuestMemoryRange, GuestMemoryReadError, GuestMemoryReader,
    PluginAppRandomConfig, PluginSwitch, PluginWhiteboxDoorbell, QemuPluginId,
    QemuPluginTargetArchitecture, QemuPluginTb, QemuRequestShutdownFn,
    WHITEBOX_DOORBELL_AARCH64_ABI, WHITEBOX_DOORBELL_AARCH64_HINT_BYTES,
    WHITEBOX_DOORBELL_X86_64_ABI, WHITEBOX_DOORBELL_X86_64_OUT_IMM8_AL_BYTES,
    WhiteboxDoorbellCapabilities, WhiteboxDoorbellFrame, WhiteboxDoorbellRegistrationPlan,
    WhiteboxDoorbellSetupResources, WhiteboxDoorbellSetupValidation, WhiteboxDoorbellTrapEvent,
    WhiteboxMarkerPayload, WhiteboxMarkerSinkError, decode_whitebox_marker_payload,
    handle_whitebox_doorbell_callback,
};

mod api;
mod app_random;
mod error;
mod guest_introspection;
mod location;
mod marker;
mod selectable;
#[cfg(test)]
mod test_restore;
pub(crate) use api::LiveWhiteboxApis;
use api::{QemuPluginRegDescriptor, QemuPluginRegister};
use app_random::LiveAppRandomState;
use crucible_protocol::app_random_branch_plan::AppRandomBranchPlan;
use crucible_protocol::app_random_transport::app_random_stream_name_belongs_to_node;
use crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan;
pub use error::LiveWhiteboxError;
use error::write_stderr;
use location::{LiveWhiteboxInstructionLocation, LiveWhiteboxTbEntry};
use marker::LiveMarkerSink;
pub(crate) use marker::LiveWhiteboxMarkerShmemProducer;
pub(crate) use selectable::LiveSelectableReplyShmemConsumer;
#[cfg(test)]
pub(super) use test_restore::install_app_random_restore_state_for_test;

const QEMU_PLUGIN_CB_R_REGS: c_int = 1;
const QEMU_PLUGIN_CB_NO_REGS: c_int = 0;
const MAX_LIVE_WHITEBOX_VCPUS: usize = 64;

static LIVE_WHITEBOX_STATE: AtomicPtr<LiveWhiteboxState> = AtomicPtr::new(std::ptr::null_mut());
static LIVE_APP_RANDOM_STATE: AtomicPtr<LiveAppRandomState> = AtomicPtr::new(std::ptr::null_mut());

/// Restores the launch-authenticated app-random continuation before restore ACK.
pub(super) fn restore_app_random_continuation() -> Result<(), LiveWhiteboxError> {
    let Some(mut app_random) = NonNull::new(LIVE_APP_RANDOM_STATE.load(Ordering::Acquire)) else {
        return Ok(());
    };
    // SAFETY: publication retains the state for QEMU's process lifetime. The
    // deterministic single-threaded RR model serializes this logical-restore
    // callback with white-box execution callbacks.
    unsafe { app_random.as_mut() }.restore_continuation()
}

/// Restores the launch-authenticated selectable continuation before restore ACK.
pub(super) fn restore_selectable_continuation() -> Result<(), LiveWhiteboxError> {
    let Some(mut state) = NonNull::new(LIVE_WHITEBOX_STATE.load(Ordering::Acquire)) else {
        return Ok(());
    };
    // SAFETY: publication retains the state for QEMU's process lifetime. The
    // deterministic single-threaded RR model serializes this logical-restore
    // callback with white-box execution callbacks.
    let state = unsafe { state.as_mut() };
    state.selectable.as_mut().map_or(
        Ok(()),
        selectable::LiveSelectableState::restore_continuation,
    )
}

/// Delivers one queued host reply at the exact vCPU resume boundary.
pub(super) fn deliver_selectable_reply_on_vcpu_resume(
    vcpu_index: u32,
    current_icount: u64,
) -> Result<(), LiveWhiteboxError> {
    let Some(mut state) = NonNull::new(LIVE_WHITEBOX_STATE.load(Ordering::Acquire)) else {
        return Ok(());
    };
    // SAFETY: publication retains this state for QEMU's process lifetime. The
    // deterministic RR model serializes the resume callback with doorbell
    // execution callbacks that mutate the same catalog.
    let state = unsafe { state.as_mut() };
    state.selectable.as_mut().map_or(Ok(()), |selectable| {
        let mut writer = selectable::LiveSelectableGuestMemoryWriter::new(
            state.apis,
            vcpu_index,
            current_icount,
        );
        selectable.deliver_reply(current_icount, vcpu_index, &mut writer)
    })
}

#[derive(Clone, Copy, Default)]
struct LiveWhiteboxRegisters {
    pointer: Option<NonNull<QemuPluginRegister>>,
    length: Option<NonNull<QemuPluginRegister>>,
}

impl LiveWhiteboxRegisters {
    const fn complete(self, _architecture: QemuPluginTargetArchitecture) -> bool {
        self.pointer.is_some() && self.length.is_some()
    }
}

/// Heap-stable callback state retained by the process-lifetime runtime owner.
pub(crate) struct LiveWhiteboxState {
    apis: LiveWhiteboxApis,
    architecture: QemuPluginTargetArchitecture,
    doorbell: PluginWhiteboxDoorbell,
    registers: [LiveWhiteboxRegisters; MAX_LIVE_WHITEBOX_VCPUS],
    tb_entries: [LiveWhiteboxTbEntry; MAX_LIVE_WHITEBOX_VCPUS],
    vcpu_count: usize,
    request_shutdown: QemuRequestShutdownFn,
    marker_sink: LiveMarkerSink,
    app_random: Option<LiveAppRandomState>,
    selectable: Option<selectable::LiveSelectableState>,
    guest_introspection: guest_introspection::LiveGuestIntrospectionState,
}

pub(crate) struct LiveWhiteboxShmem {
    marker_output: LiveWhiteboxMarkerShmemProducer,
    selectable_reply_input: selectable::LiveSelectableReplyShmemConsumer,
    guest_introspection_rings: crucible_shmem::DetachedPluginGuestIntrospectionRings,
}

/// Process-control callbacks owned by the joined live runtime.
#[derive(Clone, Copy)]
pub(crate) struct LiveWhiteboxProcessControl {
    request_shutdown: QemuRequestShutdownFn,
    request_vmstop: crate::QemuRequestVmstopFn,
}

impl LiveWhiteboxProcessControl {
    pub(crate) const fn new(
        request_shutdown: QemuRequestShutdownFn,
        request_vmstop: crate::QemuRequestVmstopFn,
    ) -> Self {
        Self {
            request_shutdown,
            request_vmstop,
        }
    }
}

/// Borrowed launch-authenticated plans transferred into live state.
pub(crate) struct LiveWhiteboxLaunchPlans<'a> {
    app_random_config: Option<&'a PluginAppRandomConfig>,
    app_random_branch_plan: &'a AppRandomBranchPlan,
    selectable_catalog_plan: Option<&'a SelectableCatalogPlan>,
}

impl<'a> LiveWhiteboxLaunchPlans<'a> {
    pub(crate) const fn new(
        app_random_config: Option<&'a PluginAppRandomConfig>,
        app_random_branch_plan: &'a AppRandomBranchPlan,
        selectable_catalog_plan: Option<&'a SelectableCatalogPlan>,
    ) -> Self {
        Self {
            app_random_config,
            app_random_branch_plan,
            selectable_catalog_plan,
        }
    }
}

impl LiveWhiteboxShmem {
    pub(crate) const fn new(
        marker_output: LiveWhiteboxMarkerShmemProducer,
        selectable_reply_input: selectable::LiveSelectableReplyShmemConsumer,
        guest_introspection_rings: crucible_shmem::DetachedPluginGuestIntrospectionRings,
    ) -> Self {
        Self {
            marker_output,
            selectable_reply_input,
            guest_introspection_rings,
        }
    }
}

/// Architecture-specific trap identity admitted by setup validation.
#[derive(Clone, Copy)]
pub(crate) struct LiveWhiteboxTarget {
    architecture: QemuPluginTargetArchitecture,
    setup_attestation: Option<crate::WhiteboxSetupAttestation>,
}

impl LiveWhiteboxTarget {
    /// Binds the observed QEMU target to its setup-time trap attestation.
    pub(crate) const fn new(
        architecture: QemuPluginTargetArchitecture,
        setup_attestation: Option<crate::WhiteboxSetupAttestation>,
    ) -> Self {
        Self {
            architecture,
            setup_attestation,
        }
    }
}

impl LiveWhiteboxState {
    /// Builds fail-closed live state after setup collision validation.
    ///
    /// # Errors
    ///
    /// Returns [`LiveWhiteboxError`] when the vCPU count is unsupported or the
    /// safe doorbell registration plan rejects its capabilities or setup state.
    pub(crate) fn new(
        apis: LiveWhiteboxApis,
        target: LiveWhiteboxTarget,
        vcpu_count: u32,
        process_control: LiveWhiteboxProcessControl,
        shmem: LiveWhiteboxShmem,
        launch_plans: LiveWhiteboxLaunchPlans<'_>,
    ) -> Result<Self, LiveWhiteboxError> {
        let architecture = target.architecture;
        let expected_attestation = match architecture {
            QemuPluginTargetArchitecture::X86_64 => {
                crate::WhiteboxSetupAttestation::X86Port00e7UnclaimedV1
            }
            QemuPluginTargetArchitecture::Aarch64 => {
                crate::WhiteboxSetupAttestation::Aarch64Hint4cInertV1
            }
        };
        if target.setup_attestation != Some(expected_attestation) {
            return Err(LiveWhiteboxError::SetupAttestationMissing);
        }
        let vcpu_count = usize::try_from(vcpu_count).map_err(|_source| {
            LiveWhiteboxError::UnsupportedVcpuCount {
                vcpu_count: u64::from(vcpu_count),
                maximum: MAX_LIVE_WHITEBOX_VCPUS,
            }
        })?;
        if vcpu_count == 0 || vcpu_count > MAX_LIVE_WHITEBOX_VCPUS {
            return Err(LiveWhiteboxError::UnsupportedVcpuCount {
                vcpu_count: vcpu_count as u64,
                maximum: MAX_LIVE_WHITEBOX_VCPUS,
            });
        }

        let abi = match architecture {
            QemuPluginTargetArchitecture::X86_64 => WHITEBOX_DOORBELL_X86_64_ABI,
            QemuPluginTargetArchitecture::Aarch64 => WHITEBOX_DOORBELL_AARCH64_ABI,
        };
        let doorbell = PluginWhiteboxDoorbell::from_abi(PluginSwitch::On, abi, MAX_FRAME_DATA);
        let validation = WhiteboxDoorbellSetupValidation::validate(
            doorbell.trap(),
            WhiteboxDoorbellSetupResources::from_observed_resources(&[], &[]),
        );
        let capabilities = WhiteboxDoorbellCapabilities::bidirectional();
        let plan = doorbell
            .registration_plan(capabilities, validation)
            .map_err(|source| LiveWhiteboxError::RegistrationPlan {
                message: source.to_string(),
            })?;
        if !matches!(plan, WhiteboxDoorbellRegistrationPlan::Install { .. }) {
            return Err(LiveWhiteboxError::RegistrationPlan {
                message: "enabled live white-box plan did not install a trap".to_owned(),
            });
        }

        if launch_plans.app_random_config.is_none()
            && !launch_plans.app_random_branch_plan.entries().is_empty()
        {
            return Err(LiveWhiteboxError::RegistrationPlan {
                message: "app-random branch plan requires an enabled app-random producer"
                    .to_owned(),
            });
        }
        if launch_plans.app_random_config.is_some_and(|config| {
            launch_plans
                .app_random_branch_plan
                .entries()
                .iter()
                .any(|entry| {
                    !app_random_stream_name_belongs_to_node(entry.stream_name(), config.node_name())
                })
        }) {
            return Err(LiveWhiteboxError::RegistrationPlan {
                message: "app-random branch plan names another producer node".to_owned(),
            });
        }
        let app_random = launch_plans
            .app_random_config
            .map(|config| {
                doorbell
                    .require_guest_input_capability(capabilities)
                    .map(|capability| {
                        LiveAppRandomState::new(
                            config,
                            launch_plans.app_random_branch_plan,
                            capability,
                        )
                    })
            })
            .transpose()
            .map_err(|source| LiveWhiteboxError::RegistrationPlan {
                message: source.to_string(),
            })?;
        let guest_input_capability = doorbell
            .require_guest_input_capability(capabilities)
            .map_err(|source| LiveWhiteboxError::RegistrationPlan {
                message: source.to_string(),
            })?;
        let selectable = launch_plans
            .selectable_catalog_plan
            .map(|plan| {
                selectable::LiveSelectableState::new(
                    plan,
                    guest_input_capability,
                    process_control.request_vmstop,
                    shmem.selectable_reply_input,
                )
            })
            .transpose()
            .map_err(|source| LiveWhiteboxError::RegistrationPlan {
                message: source.to_string(),
            })?;

        Ok(Self {
            apis,
            architecture,
            doorbell,
            registers: [LiveWhiteboxRegisters::default(); MAX_LIVE_WHITEBOX_VCPUS],
            tb_entries: [LiveWhiteboxTbEntry::default(); MAX_LIVE_WHITEBOX_VCPUS],
            vcpu_count,
            request_shutdown: process_control.request_shutdown,
            marker_sink: LiveMarkerSink::new(shmem.marker_output),
            app_random,
            selectable,
            guest_introspection: guest_introspection::LiveGuestIntrospectionState::new(
                shmem.guest_introspection_rings,
                guest_input_capability,
            ),
        })
    }

    /// Publishes the state and registers translation callbacks.
    ///
    /// # Errors
    ///
    /// Returns [`LiveWhiteboxError::StateAlreadyPublished`] when another live
    /// white-box owner is already installed.
    pub(crate) fn register(&mut self, plugin_id: QemuPluginId) -> Result<(), LiveWhiteboxError> {
        LIVE_WHITEBOX_STATE
            .compare_exchange(
                std::ptr::null_mut(),
                std::ptr::from_mut(self),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_existing| LiveWhiteboxError::StateAlreadyPublished)?;
        if let Some(app_random) = self.app_random.as_mut() {
            LIVE_APP_RANDOM_STATE.store(std::ptr::from_mut(app_random), Ordering::Release);
        }
        (self.apis.register_tb_trans_cb)(
            plugin_id,
            Some(crucible_qemu_plugin_live_whitebox_tb_trans_cb),
        );
        Ok(())
    }

    fn initialize_vcpu(&mut self, vcpu_index: usize) -> Result<(), LiveWhiteboxError> {
        if vcpu_index >= self.vcpu_count {
            return Err(LiveWhiteboxError::UnexpectedVcpu {
                vcpu_index,
                vcpu_count: self.vcpu_count,
            });
        }

        let array = (self.apis.get_registers)();
        let Some(array) = NonNull::new(array) else {
            return Err(LiveWhiteboxError::RegisterListUnavailable { vcpu_index });
        };
        // QEMU retains the descriptor array for the duration of this callback.
        // SAFETY: `data` contains exactly `len` initialized register descriptors.
        let descriptors = unsafe {
            std::slice::from_raw_parts(
                array.as_ref().data.cast::<QemuPluginRegDescriptor>(),
                array.as_ref().len as usize,
            )
        };
        let mut registers = LiveWhiteboxRegisters::default();
        for descriptor in descriptors {
            if descriptor.name.is_null() {
                continue;
            }
            // SAFETY: QEMU documents descriptor names as valid NUL-terminated
            // strings retained for the plugin lifetime.
            let raw_name = unsafe { CStr::from_ptr(descriptor.name) }.to_bytes();
            let name = raw_name.strip_prefix(b"%").unwrap_or(raw_name);
            let handle = NonNull::new(descriptor.handle);
            match (self.architecture, name) {
                (QemuPluginTargetArchitecture::X86_64, b"rax")
                | (QemuPluginTargetArchitecture::Aarch64, b"x0") => {
                    registers.pointer = handle;
                }
                (QemuPluginTargetArchitecture::X86_64, b"rcx")
                | (QemuPluginTargetArchitecture::Aarch64, b"x1") => {
                    registers.length = handle;
                }
                _ => {}
            }
        }
        (self.apis.g_array_free)(array.as_ptr(), true);
        if !registers.complete(self.architecture) {
            return Err(LiveWhiteboxError::RequiredRegistersUnavailable { vcpu_index });
        }
        self.registers[vcpu_index] = registers;
        Ok(())
    }

    fn service(
        &mut self,
        vcpu_index: usize,
        location: LiveWhiteboxInstructionLocation,
    ) -> Result<(), LiveWhiteboxError> {
        if vcpu_index >= self.vcpu_count {
            return Err(LiveWhiteboxError::UnexpectedVcpu {
                vcpu_index,
                vcpu_count: self.vcpu_count,
            });
        }
        let registers = self.registers[vcpu_index];
        let address = self.read_register_u64(
            registers
                .pointer
                .ok_or(LiveWhiteboxError::RequiredRegistersUnavailable { vcpu_index })?,
        )?;
        let len_u64 = self.read_register_u64(
            registers
                .length
                .ok_or(LiveWhiteboxError::RequiredRegistersUnavailable { vcpu_index })?,
        )?;
        let len = usize::try_from(len_u64)
            .map_err(|_source| LiveWhiteboxError::PayloadLengthOverflow { len: len_u64 })?;
        if len > MAX_FRAME_DATA {
            return Err(LiveWhiteboxError::PayloadTooLarge {
                len,
                maximum: MAX_FRAME_DATA,
            });
        }
        // The preceding callback at this TB's entry captured QEMU's exact,
        // non-mutating coordinate in the API context where it is valid.
        let current_icount = location.current_icount(self.tb_entries[vcpu_index])?;
        let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(
            vcpu_index as u32,
            current_icount,
            GuestMemoryRange::new(GuestMemoryAddressSpace::Virtual, address, len),
        );
        let mut reader = LiveGuestMemoryReader { apis: self.apis };
        let payload = reader
            .read_guest_memory(
                event.vcpu_index(),
                event.current_icount(),
                event.payload_range(),
            )
            .map_err(|source| LiveWhiteboxError::Callback {
                message: source.to_string(),
            })?;
        if guest_introspection::is_exchange(&payload) {
            self.handle_guest_introspection(&mut reader, event, &payload)
        } else if app_random::is_request(&payload) {
            self.handle_app_random(&mut reader, event, current_icount, vcpu_index)
        } else if selectable::is_message(&payload) {
            let selectable = self
                .selectable
                .as_mut()
                .ok_or(LiveWhiteboxError::SelectableNotConfigured)?;
            let outcome = selectable.handle(&self.doorbell, self.apis, &mut reader, event)?;
            if matches!(outcome, crate::SelectableDoorbellOutcome::Pending { .. }) {
                let record = selectable.pending_transport_record()?;
                self.marker_sink.output.record_selectable_pending(
                    current_icount,
                    vcpu_index as u32,
                    &record,
                )?;
            }
            Ok(())
        } else {
            if is_setup_complete_marker(&payload)
                && let Some(selectable) = self.selectable.as_mut()
            {
                // Reconcile required declarations before the readiness marker
                // can enter the host-observable output ring.
                selectable.freeze()?;
            }
            let marker = handle_whitebox_doorbell_callback(
                &self.doorbell,
                &mut reader,
                &mut self.marker_sink,
                event,
            )
            .map_err(|source| LiveWhiteboxError::Callback {
                message: source.to_string(),
            })?;
            if let WhiteboxMarkerPayload::Event(event) = marker.decoded_payload() {
                let status = (self.apis.fault_ready_marker)(
                    event.name.as_ptr().cast(),
                    event.name.len(),
                    marker.marker_icount(),
                );
                if status < 0 {
                    return Err(LiveWhiteboxError::Callback {
                        message: format!(
                            "QEMU rejected ready-marker observation `{}` with status {status}",
                            event.name
                        ),
                    });
                }
            }
            Ok(())
        }
    }

    fn observe_tb_entry(
        &mut self,
        vcpu_index: usize,
        tb_insns: u32,
    ) -> Result<(), LiveWhiteboxError> {
        if vcpu_index >= self.vcpu_count {
            return Err(LiveWhiteboxError::UnexpectedVcpu {
                vcpu_index,
                vcpu_count: self.vcpu_count,
            });
        }
        let mut icount = 0;
        if (self.apis.icount_at_tb_entry)(u64::from(tb_insns), &mut icount) != 0 {
            return Err(LiveWhiteboxError::IcountObservation);
        }
        self.tb_entries[vcpu_index] = LiveWhiteboxTbEntry { tb_insns, icount };
        Ok(())
    }

    fn read_register_u64(
        &self,
        handle: NonNull<QemuPluginRegister>,
    ) -> Result<u64, LiveWhiteboxError> {
        let array = (self.apis.g_byte_array_new)();
        let Some(array) = NonNull::new(array) else {
            return Err(LiveWhiteboxError::ByteArrayAllocation);
        };
        let size = (self.apis.read_register)(handle.as_ptr(), array.as_ptr());
        if size <= 0 {
            (self.apis.g_byte_array_free)(array.as_ptr(), true);
            return Err(LiveWhiteboxError::RegisterRead);
        }
        let bytes = {
            // GLib retains the array until the explicit free below.
            // SAFETY: QEMU sets `data` and `len` to the initialized register bytes.
            unsafe { std::slice::from_raw_parts(array.as_ref().data, array.as_ref().len as usize) }
        };
        let mut value = 0_u64;
        for (shift, byte) in bytes.iter().copied().take(8).enumerate() {
            value |= u64::from(byte) << (shift * 8);
        }
        (self.apis.g_byte_array_free)(array.as_ptr(), true);
        Ok(value)
    }

    fn fail_loud(&self, error: &LiveWhiteboxError) {
        let message = format!("crucible-qemu-plugin: live white-box callback failed: {error}\n");
        let _written = write_stderr(message.as_bytes());
        (self.request_shutdown)(1);
    }
}

fn is_setup_complete_marker(payload: &[u8]) -> bool {
    WhiteboxDoorbellFrame::decode_bounded(payload, MAX_FRAME_DATA)
        .ok()
        .and_then(|frame| decode_whitebox_marker_payload(&frame).ok())
        == Some(WhiteboxMarkerPayload::Lifecycle(
            crate::WhiteboxLifecycleMarkerEvent::SetupComplete,
        ))
}

struct LiveGuestMemoryReader {
    apis: LiveWhiteboxApis,
}

impl GuestMemoryReader for LiveGuestMemoryReader {
    fn read_guest_memory(
        &mut self,
        _vcpu_index: u32,
        _current_icount: u64,
        range: GuestMemoryRange,
    ) -> Result<Vec<u8>, GuestMemoryReadError> {
        if !matches!(range.address_space(), GuestMemoryAddressSpace::Virtual) {
            return Err(GuestMemoryReadError::new(
                "live white-box adapter requires a virtual payload range",
            ));
        }
        let array = (self.apis.g_byte_array_new)();
        let Some(array) = NonNull::new(array) else {
            return Err(GuestMemoryReadError::new(
                "GLib byte-array allocation failed",
            ));
        };
        let read =
            (self.apis.read_memory_vaddr)(range.guest_address(), array.as_ptr(), range.len());
        if !read {
            (self.apis.g_byte_array_free)(array.as_ptr(), true);
            return Err(GuestMemoryReadError::new(
                "qemu_plugin_read_memory_vaddr failed",
            ));
        }
        let bytes = {
            // The returned bytes are copied before the GLib array is freed.
            // SAFETY: QEMU sets `data` and `len` to the initialized memory result.
            unsafe { std::slice::from_raw_parts(array.as_ref().data, array.as_ref().len as usize) }
        }
        .to_vec();
        (self.apis.g_byte_array_free)(array.as_ptr(), true);
        Ok(bytes)
    }
}

extern "C" fn crucible_qemu_plugin_live_whitebox_tb_trans_cb(
    _plugin_id: QemuPluginId,
    tb: *mut QemuPluginTb,
) {
    let Some(mut state) = NonNull::new(LIVE_WHITEBOX_STATE.load(Ordering::Acquire)) else {
        return;
    };
    if tb.is_null() {
        return;
    }
    // SAFETY: publication retains the state for QEMU's process lifetime, and
    // the validated single-threaded RR execution model serializes callbacks.
    let state = unsafe { state.as_mut() };
    let count = (state.apis.tb_n_insns)(tb);
    let mut registered_entry_callback = false;
    for index in 0..count {
        let insn = (state.apis.tb_get_insn)(tb, index);
        if insn.is_null() {
            continue;
        }
        let mut bytes = [0_u8; 4];
        let copied = (state.apis.insn_data)(insn, bytes.as_mut_ptr().cast(), bytes.len());
        let trap_bytes: &[u8] = match state.architecture {
            QemuPluginTargetArchitecture::X86_64 => &WHITEBOX_DOORBELL_X86_64_OUT_IMM8_AL_BYTES,
            QemuPluginTargetArchitecture::Aarch64 => &WHITEBOX_DOORBELL_AARCH64_HINT_BYTES,
        };
        if bytes[..copied.min(bytes.len())] == *trap_bytes {
            let location = match LiveWhiteboxInstructionLocation::new(count, index) {
                Ok(location) => location,
                Err(error) => {
                    state.fail_loud(&error);
                    return;
                }
            };
            if !registered_entry_callback {
                (state.apis.register_tb_exec_cb)(
                    tb,
                    Some(crucible_qemu_plugin_live_whitebox_tb_exec_cb),
                    QEMU_PLUGIN_CB_NO_REGS,
                    location.tb_userdata(),
                );
                registered_entry_callback = true;
            }
            (state.apis.register_insn_exec_cb)(
                insn,
                Some(crucible_qemu_plugin_live_whitebox_insn_exec_cb),
                QEMU_PLUGIN_CB_R_REGS,
                location.into_userdata(),
            );
        }
    }
}

extern "C" fn crucible_qemu_plugin_live_whitebox_tb_exec_cb(
    vcpu_index: c_uint,
    userdata: *mut c_void,
) {
    let Some(mut state) = NonNull::new(LIVE_WHITEBOX_STATE.load(Ordering::Acquire)) else {
        return;
    };
    // SAFETY: publication retains the state for QEMU's process lifetime, and
    // the validated single-threaded RR execution model serializes callbacks.
    let state = unsafe { state.as_mut() };
    let tb_insns = LiveWhiteboxInstructionLocation::tb_insns_from_userdata(userdata);
    if let Err(error) =
        tb_insns.and_then(|tb_insns| state.observe_tb_entry(vcpu_index as usize, tb_insns))
    {
        state.fail_loud(&error);
    }
}

extern "C" fn crucible_qemu_plugin_live_whitebox_insn_exec_cb(
    vcpu_index: c_uint,
    userdata: *mut c_void,
) {
    let Some(mut state) = NonNull::new(LIVE_WHITEBOX_STATE.load(Ordering::Acquire)) else {
        return;
    };
    // SAFETY: publication retains the state for QEMU's process lifetime, and
    // the validated single-threaded RR execution model serializes callbacks.
    let state = unsafe { state.as_mut() };
    let location = LiveWhiteboxInstructionLocation::from_userdata(userdata);
    if let Err(error) = location.and_then(|location| state.service(vcpu_index as usize, location)) {
        state.fail_loud(&error);
    }
}

/// Initializes the register handles for one live vCPU.
pub(crate) extern "C" fn crucible_qemu_plugin_live_whitebox_vcpu_init_cb(
    _plugin_id: QemuPluginId,
    vcpu_index: c_uint,
) {
    let Some(mut state) = NonNull::new(LIVE_WHITEBOX_STATE.load(Ordering::Acquire)) else {
        return;
    };
    // SAFETY: publication retains the state for QEMU's process lifetime, and
    // the validated single-threaded RR execution model serializes callbacks.
    let state = unsafe { state.as_mut() };
    if let Err(error) = state.initialize_vcpu(vcpu_index as usize) {
        state.fail_loud(&error);
    }
}
