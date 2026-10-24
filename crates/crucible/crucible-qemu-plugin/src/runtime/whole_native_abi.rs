//! GPL-local native whole-controller ABI and original source readback.
//!
//! These C layouts remain inside the QEMU process. The socket and shared-memory
//! protocols use the independently versioned explicit byte codecs; no instance
//! of these pointer-bearing records may be serialized or shared with the host.

use std::ffi::{c_int, c_void};

use crucible_qemu_protocol::whole_control::{WholeControlError, staged::StagedControlProfile};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct NativeWholePolicy {
    pub(crate) version: u32,
    pub(crate) size: u32,
    pub(crate) scope: [u8; 32],
    pub(crate) request_byte_limit: u64,
    pub(crate) input_byte_limit: u64,
    pub(crate) output_byte_limit: u64,
    pub(crate) output_record_limit: u64,
    pub(crate) cpu_retirement_limit: u64,
    pub(crate) event_step_limit: u64,
    pub(crate) flags: u32,
    pub(crate) reserved: u32,
}

impl NativeWholePolicy {
    pub(crate) fn from_profile(profile: &StagedControlProfile) -> Result<Self, WholeControlError> {
        profile.validate()?;
        let compute = &profile.compute;
        Ok(Self {
            version: 1,
            size: std::mem::size_of::<Self>() as u32,
            scope: compute.scope,
            request_byte_limit: u64::from(compute.body_byte_limit),
            input_byte_limit: compute.input_byte_limit,
            output_byte_limit: compute.output_byte_limit,
            output_record_limit: compute.output_record_limit,
            cpu_retirement_limit: compute.cpu_retirement_limit,
            event_step_limit: compute.event_step_limit,
            flags: 0,
            reserved: 0,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct NativeWholeBudgetHistory {
    pub(crate) version: u32,
    pub(crate) size: u32,
    pub(crate) operation_limit: u64,
    pub(crate) request_byte_limit: u64,
    pub(crate) result_byte_limit: u64,
    pub(crate) history_byte_limit: u64,
    pub(crate) input_record_limit: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct NativeWholeBudget {
    pub(crate) history: NativeWholeBudgetHistory,
    pub(crate) input_stage_limit: u64,
    pub(crate) stage_byte_limit: u64,
    pub(crate) binding_byte_limit: u64,
}

impl NativeWholeBudget {
    pub(crate) fn from_profile(profile: &StagedControlProfile) -> Result<Self, WholeControlError> {
        profile.validate()?;
        let compute = &profile.compute;
        Ok(Self {
            history: NativeWholeBudgetHistory {
                version: 2,
                size: std::mem::size_of::<Self>() as u32,
                operation_limit: u64::from(compute.operation_capacity),
                request_byte_limit: u64::from(compute.body_byte_limit),
                result_byte_limit: u64::from(compute.body_byte_limit),
                history_byte_limit: compute.native_history_byte_limit,
                input_record_limit: compute.input_record_limit,
            },
            input_stage_limit: u64::from(profile.input_stage_limit),
            stage_byte_limit: u64::from(profile.stage_body_byte_limit),
            binding_byte_limit: u64::from(compute.body_byte_limit),
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct NativeWholeIoTotals {
    pub(crate) input_records: u64,
    pub(crate) input_bytes: u64,
    pub(crate) output_records: u64,
    pub(crate) output_bytes: u64,
}

pub(crate) type AdoptHeld = extern "C" fn(*mut c_void, u64, u64, u64) -> c_int;
pub(crate) type ControlBoundary = extern "C" fn(*mut c_void, u32, u64) -> c_int;
pub(crate) type GetBody = extern "C" fn(*mut c_void, *mut u8, usize, *mut usize) -> c_int;
pub(crate) type ReserveResult =
    extern "C" fn(*mut c_void, *const u8, usize, usize, u64, u64, *mut *mut c_void) -> c_int;
pub(crate) type Scope = extern "C" fn(*mut c_void, u64, u64, *mut c_void) -> c_int;
pub(crate) type RetainResult = extern "C" fn(*mut c_void, *mut c_void, *const u8, usize) -> c_int;
pub(crate) type RetainAcknowledgement = extern "C" fn(*mut c_void, *const u8, usize) -> c_int;
pub(crate) type PrepareInputs =
    extern "C" fn(*mut c_void, u64, u64, *mut c_void, *const u8, usize, u64, u64) -> c_int;
pub(crate) type ServiceInputs = extern "C" fn(*mut c_void, u64, u64, *mut c_void, u64) -> c_int;
pub(crate) type Collect = extern "C" fn(
    *mut c_void,
    u64,
    u64,
    *mut c_void,
    u64,
    *mut u8,
    usize,
    *mut usize,
    *mut NativeWholeIoTotals,
) -> c_int;
pub(crate) type RetireStopped = extern "C" fn(
    *mut c_void,
    u64,
    u64,
    *mut c_void,
    u64,
    u64,
    u64,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
) -> c_int;
pub(crate) type ReadOriginalBinding =
    extern "C" fn(*mut c_void, u64, u64, u64, *mut u8, usize, *mut usize) -> c_int;
pub(crate) type ReserveStage = extern "C" fn(
    *mut c_void,
    u64,
    u64,
    *const u8,
    usize,
    *mut *mut c_void,
    *mut NativeWholeIoTotals,
    *mut u8,
) -> c_int;
pub(crate) type ValidateStage =
    extern "C" fn(*mut c_void, u64, u64, *mut c_void, *const u8, usize) -> c_int;
pub(crate) type RefuseLocalScope = extern "C" fn(*mut c_void, u64, u64, *mut c_void);
/// Reports the earliest remaining selected input strictly after the current cut.
pub(crate) type NextInputs =
    extern "C" fn(*mut c_void, u64, u64, *mut c_void, u64, u64, *mut u64) -> c_int;
/// Settles actual outputs while the original paired callback loan remains live.
pub(crate) type SettleOutputs = extern "C" fn(*mut c_void, u64, u64, *mut c_void, u64) -> c_int;

pub(crate) type GetStageCommit =
    extern "C" fn(*mut c_void, u64, u64, *mut c_void, *mut u8, usize, *mut usize) -> c_int;

#[repr(C)]
pub(crate) struct NativeWholeOpsRetained {
    pub(crate) version: u32,
    pub(crate) size: u32,
    pub(crate) adopt_held: AdoptHeld,
    pub(crate) control_boundary: ControlBoundary,
    pub(crate) get_request: GetBody,
    pub(crate) reserve_result: ReserveResult,
    pub(crate) scope_begin: Scope,
    pub(crate) scope_end: Scope,
    pub(crate) retain_result: RetainResult,
    pub(crate) get_acknowledgement: GetBody,
    pub(crate) retain_consumed_acknowledgement: RetainAcknowledgement,
}

#[repr(C)]
pub(crate) struct NativeWholeOpsService {
    pub(crate) retained: NativeWholeOpsRetained,
    pub(crate) prepare_inputs: PrepareInputs,
    pub(crate) service_inputs_at: ServiceInputs,
    pub(crate) collect_stopped: Collect,
    pub(crate) collect_uncertain: Collect,
}

#[repr(C)]
pub(crate) struct NativeWholeOpsHistory {
    pub(crate) service: NativeWholeOpsService,
    pub(crate) retire_stopped: RetireStopped,
}

#[repr(C)]
pub(crate) struct NativeWholeOps {
    pub(crate) history: NativeWholeOpsHistory,
    pub(crate) read_original_binding: ReadOriginalBinding,
    pub(crate) reserve_stage: ReserveStage,
    pub(crate) validate_stage_current: ValidateStage,
    pub(crate) retain_stage_receipt: ValidateStage,
    pub(crate) get_stage_commit: GetStageCommit,
    pub(crate) retain_consumed_stage_commit: ValidateStage,
    pub(crate) validate_stage_references: ValidateStage,
    pub(crate) refuse_local_scope: RefuseLocalScope,
    pub(crate) publish_retired: RetireStopped,
    pub(crate) next_inputs_at: NextInputs,
    pub(crate) settle_outputs_at: SettleOutputs,
    pub(crate) offer_source_ready: RetainAcknowledgement,
    pub(crate) get_source_ready_ack: GetBody,
    pub(crate) publish_consumed_source_ready_ack: RetainAcknowledgement,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct NativeWholeEndpoint {
    pub(crate) present: u32,
    pub(crate) read_only: u32,
    pub(crate) owner: *mut c_void,
    pub(crate) queue: *mut c_void,
    pub(crate) pending: *mut c_void,
    pub(crate) userdata: [*mut c_void; 3],
    pub(crate) callbacks: [usize; 8],
    pub(crate) transport_epoch: u64,
    pub(crate) next_request_id: u64,
    pub(crate) pending_request_id: u64,
    pub(crate) pending_response_capacity: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct NativeWholeClock {
    pub(crate) raw: u64,
    pub(crate) semantic_ps: u64,
    pub(crate) sim_bias_ps: u64,
    pub(crate) anchor_raw: u64,
    pub(crate) anchor_ps: u64,
    pub(crate) park_ps: u64,
    pub(crate) bias_ps_high: i64,
    pub(crate) bias_ps_low: u64,
    pub(crate) mode: u32,
    pub(crate) instruction_ps: u32,
    pub(crate) time_shift: u32,
    pub(crate) ns_divisor: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct NativeWholeBinding {
    pub(crate) version: u32,
    pub(crate) size: u32,
    pub(crate) clock: NativeWholeClock,
    pub(crate) packet: NativeWholeEndpoint,
    pub(crate) block: NativeWholeEndpoint,
    pub(crate) ninep: NativeWholeEndpoint,
}

impl Default for NativeWholeBinding {
    fn default() -> Self {
        Self {
            // The genuine getter requires the caller's exact destination ABI
            // before it copies any original source-owned observation.
            version: 1,
            size: std::mem::size_of::<Self>() as u32,
            clock: NativeWholeClock::default(),
            packet: NativeWholeEndpoint::default(),
            block: NativeWholeEndpoint::default(),
            ninep: NativeWholeEndpoint::default(),
        }
    }
}

pub(crate) type ReadNativeBinding = extern "C" fn(*mut NativeWholeBinding) -> c_int;
pub(crate) type RegisterWholeController = extern "C" fn(
    u64,
    *const NativeWholePolicy,
    *const NativeWholeBudget,
    *const NativeWholeOps,
    *mut c_void,
) -> c_int;
pub(crate) type OfferStage = extern "C" fn(*const u8, usize) -> c_int;
pub(crate) type AuthenticateSetup = extern "C" fn(u64, c_int, *const u8) -> c_int;
pub(crate) type ClaimControl = extern "C" fn(u64, c_int, *mut c_int) -> c_int;
pub(crate) type ReadEarlySetup = extern "C" fn(u64, *mut *const u8, *mut usize, *mut u8) -> c_int;

/// Borrows immutable bytes owned by the same genuine early native constructor.
///
/// This GPL-local view supplies only constructor accounting and correlation.
/// No pointer escapes onto the public control or shared-memory protocol.
pub(crate) struct NativeEarlySetup<'a> {
    pub(crate) body: &'a [u8],
    pub(crate) digest: [u8; 32],
}

pub(crate) struct NativeWholeApis {
    pub(crate) claim_control: ClaimControl,
    #[expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )]
    pub(crate) read_early_setup: ReadEarlySetup,
    pub(crate) authenticate_setup: AuthenticateSetup,
    #[expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )]
    pub(crate) read_native_binding: ReadNativeBinding,
    #[expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )]
    pub(crate) retirement: super::whole_native_retirement::NativeRetirementApi,
    pub(crate) register: RegisterWholeController,
    #[expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )]
    pub(crate) offer_stage: OfferStage,
}

impl NativeWholeApis {
    /// Probes genuine early selection before any ordinary socket duplication.
    ///
    /// Missing exports preserve an older ordinary source. An available getter
    /// must authenticate its own literal original loader context; only its exact
    /// ENOENT response denotes ordinary absence. Selected or refused contexts
    /// never fall through to the legacy installer, including partial SDKs.
    pub(crate) fn probe_early_selection(
        plugin: u64,
    ) -> Result<Option<NativeEarlySetup<'static>>, c_int> {
        // SAFETY: The static name pins the exact source-owned immutable getter.
        // Its response, not symbol availability, authenticates selection.
        let symbol = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"qemu_plugin_crucible_whole_read_setup_v3".as_ptr(),
            )
        };
        if symbol.is_null() {
            return Ok(None);
        }
        // SAFETY: The matching public GPL-local SDK declares ReadEarlySetup.
        let read = unsafe { std::mem::transmute::<*mut c_void, ReadEarlySetup>(symbol) };
        read_original_setup(read, plugin)
    }

    /// Reads complete original setup bytes only in literal stopped installation.
    ///
    /// The native source distinguishes genuine absence from refused selection.
    /// Bounds and the full original SHA256 are checked before interpreting any
    /// body. The later same-inode SCM authentication remains mandatory.
    ///
    /// # Errors
    /// Refuses another native call context, stale selection, malformed extent
    /// or a digest that does not name the complete retained source body.
    #[expect(
        dead_code,
        reason = "The Preparing-only controller keeps genuine source adoption and execution closed."
    )]
    pub(crate) fn read_setup_body(
        &self,
        plugin: u64,
    ) -> Result<Option<NativeEarlySetup<'_>>, c_int> {
        read_original_setup(self.read_early_setup, plugin)
    }

    /// Receives the same inherited original socket through its literal one-shot claim.
    ///
    /// A successful source transfers ownership and retains only borrowed native
    /// identity. This method never duplicates the FD or creates another actor.
    pub(crate) fn claim_control_socket(
        &self,
        plugin_id: u64,
        expected_fd: c_int,
    ) -> Result<std::os::unix::net::UnixStream, c_int> {
        use std::os::fd::FromRawFd;
        let mut owned_fd = -1;
        let status = (self.claim_control)(plugin_id, expected_fd, &mut owned_fd);
        if status != 0 {
            return Err(status);
        }
        if owned_fd < 0 || owned_fd != expected_fd {
            // A malformed native response remains a stopped source refusal;
            // it cannot authorize closing an unrelated process descriptor.
            return Err(-libc::EPROTO);
        }
        // SAFETY: The genuine loader-authenticated source API transfers this
        // same inherited socket exactly once. C never closes or replaces it.
        // Its exact returned FD was checked above; no descriptor is duplicated.
        Ok(unsafe { std::os::unix::net::UnixStream::from_raw_fd(owned_fd) })
    }

    pub(crate) fn resolve() -> Option<Self> {
        // SAFETY: The name pins the source-owned one-shot original FD transfer.
        let claim = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"qemu_plugin_crucible_whole_claim_control_v1".as_ptr(),
            )
        };
        // SAFETY: Each static name pins the exact GPL-local SDK declaration.
        // Successful symbol resolution supplies no native call authorization;
        // the source independently verifies the original callback context.
        let binding = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"qemu_plugin_crucible_whole_read_native_binding_v1".as_ptr(),
            )
        };
        // SAFETY: The static name pins the exact source-owned immutable view.
        let early = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"qemu_plugin_crucible_whole_read_setup_v3".as_ptr(),
            )
        };
        // SAFETY: The static name pins the original sealed constructor handover.
        let setup = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"qemu_plugin_crucible_whole_authenticate_setup_v3".as_ptr(),
            )
        };
        // SAFETY: The static name identifies only the exact version-five ABI.
        let register = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"qemu_plugin_crucible_register_whole_controller_v5".as_ptr(),
            )
        };
        // SAFETY: The static name identifies only the source-controlled stage ABI.
        let stage = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"qemu_plugin_crucible_whole_stage_offer_v1".as_ptr(),
            )
        };
        let retirement = super::whole_native_retirement::NativeRetirementApi::resolve()?;
        if claim.is_null()
            || early.is_null()
            || setup.is_null()
            || binding.is_null()
            || register.is_null()
            || stage.is_null()
        {
            return None;
        }
        Some(Self {
            // SAFETY: The matching source SDK declares exactly ClaimControl.
            claim_control: unsafe { std::mem::transmute::<*mut c_void, ClaimControl>(claim) },
            // SAFETY: The source SDK declares exactly ReadEarlySetup.
            read_early_setup: unsafe { std::mem::transmute::<*mut c_void, ReadEarlySetup>(early) },
            // SAFETY: The source SDK declares exactly AuthenticateSetup.
            authenticate_setup: unsafe {
                std::mem::transmute::<*mut c_void, AuthenticateSetup>(setup)
            },
            // SAFETY: The resolved SDK export declares exactly ReadNativeBinding.
            read_native_binding: unsafe {
                std::mem::transmute::<*mut c_void, ReadNativeBinding>(binding)
            },
            retirement,
            // SAFETY: The resolved SDK export declares exactly RegisterWholeController.
            register: unsafe {
                std::mem::transmute::<*mut c_void, RegisterWholeController>(register)
            },
            // SAFETY: The resolved SDK export declares exactly OfferStage.
            offer_stage: unsafe { std::mem::transmute::<*mut c_void, OfferStage>(stage) },
        })
    }
}

/// Borrows the native source's immutable original body, retained until exit.
fn read_original_setup(
    read_early_setup: ReadEarlySetup,
    plugin: u64,
) -> Result<Option<NativeEarlySetup<'static>>, c_int> {
    use sha2::{Digest, Sha256};
    let mut body = std::ptr::null();
    let mut extent = 0usize;
    let mut digest = [0; 32];
    let status = (read_early_setup)(plugin, &mut body, &mut extent, digest.as_mut_ptr());
    if status == -libc::ENOENT && body.is_null() && extent == 0 && digest == [0; 32] {
        return Ok(None);
    }
    if status != 0 {
        return Err(if status < 0 { status } else { -libc::EPROTO });
    }
    if body.is_null()
        || !(36..=crucible_qemu_protocol::plugin_setup_plan::PLUGIN_SETUP_PLAN_MAX_BYTES)
            .contains(&extent)
    {
        return Err(-libc::EPROTO);
    }
    // SAFETY: The exact SDK getter verifies literal original loader
    // PID/thread/plugin/BQL context and returns its source-owned immutable
    // allocation, retained until process exit. Its bounded extent was
    // checked above. This borrowed pointer remains inside the GPL process.
    let body = unsafe { std::slice::from_raw_parts(body, extent) };
    if Sha256::digest(body)[..] != digest {
        return Err(-libc::EPROTO);
    }
    Ok(Some(NativeEarlySetup { body, digest }))
}

const _: () = {
    assert!(std::mem::size_of::<NativeWholePolicy>() == 96);
    assert!(std::mem::size_of::<NativeWholeBudgetHistory>() == 48);
    assert!(std::mem::size_of::<NativeWholeBudget>() == 72);
    assert!(std::mem::size_of::<NativeWholeIoTotals>() == 32);
    assert!(std::mem::size_of::<NativeWholeOpsRetained>() == 80);
    assert!(std::mem::size_of::<NativeWholeOpsService>() == 112);
    assert!(std::mem::size_of::<NativeWholeOpsHistory>() == 120);
    assert!(std::mem::size_of::<NativeWholeOps>() == 232);
    assert!(std::mem::size_of::<NativeWholeEndpoint>() == 152);
    assert!(std::mem::size_of::<NativeWholeClock>() == 80);
    assert!(std::mem::size_of::<NativeWholeBinding>() == 544);
    assert!(std::mem::offset_of!(NativeWholeOps, read_original_binding) == 120);
    assert!(std::mem::offset_of!(NativeWholeOps, refuse_local_scope) == 176);
    assert!(std::mem::offset_of!(NativeWholeOps, publish_retired) == 184);
    assert!(std::mem::offset_of!(NativeWholeOps, next_inputs_at) == 192);
    assert!(std::mem::offset_of!(NativeWholeOps, settle_outputs_at) == 200);
    assert!(std::mem::offset_of!(NativeWholeOps, offer_source_ready) == 208);
    assert!(std::mem::offset_of!(NativeWholeOps, get_source_ready_ack) == 216);
    assert!(std::mem::offset_of!(NativeWholeOps, publish_consumed_source_ready_ack) == 224);
    assert!(std::mem::offset_of!(NativeWholeBinding, packet) == 88);
};

#[cfg(test)]
mod early_selection_tests {
    // crucible-lint: allow panic-shortcut -- Modeled getter controls fail on invariant violations.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use sha2::{Digest, Sha256};

    static BODY: [u8; 36] = [3; 36];

    extern "C" fn modeled_selected(
        _id: u64,
        body: *mut *const u8,
        extent: *mut usize,
        digest: *mut u8,
    ) -> c_int {
        // SAFETY: These modeled getters are called only by read_original_setup,
        // which supplies valid exclusive outputs and fixed32 digest backing.
        unsafe {
            *body = BODY.as_ptr();
            *extent = BODY.len();
            std::ptr::copy_nonoverlapping(Sha256::digest(BODY).as_ptr(), digest, 32);
        }
        0
    }

    extern "C" fn modeled_ordinary(
        _id: u64,
        _body: *mut *const u8,
        _extent: *mut usize,
        _digest: *mut u8,
    ) -> c_int {
        -libc::ENOENT
    }

    extern "C" fn modeled_inconsistent_absence(
        id: u64,
        body: *mut *const u8,
        extent: *mut usize,
        digest: *mut u8,
    ) -> c_int {
        modeled_selected(id, body, extent, digest);
        -libc::ENOENT
    }

    extern "C" fn modeled_refused(
        _id: u64,
        _body: *mut *const u8,
        _extent: *mut usize,
        _digest: *mut u8,
    ) -> c_int {
        -libc::EPERM
    }

    #[test]
    fn original_early_probe_accepts_only_exact_verified_ordinary_absence() {
        assert!(read_original_setup(modeled_ordinary, 7).unwrap().is_none());
        assert_eq!(
            read_original_setup(modeled_inconsistent_absence, 7).err(),
            Some(-libc::ENOENT)
        );
        assert_eq!(
            read_original_setup(modeled_refused, 7).err(),
            Some(-libc::EPERM)
        );
    }

    #[test]
    fn original_selected_view_preserves_native_full_body_and_hash_without_allocation() {
        let selected = read_original_setup(modeled_selected, 7).unwrap().unwrap();
        assert_eq!(selected.body.as_ptr(), BODY.as_ptr());
        assert_eq!(selected.body, BODY);
        assert_eq!(&selected.digest[..], &Sha256::digest(BODY)[..]);
    }
}
