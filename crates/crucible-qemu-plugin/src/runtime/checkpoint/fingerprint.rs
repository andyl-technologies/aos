//! Enrolls the real already-entered ordinary fingerprint owner with native Source.
//!
//! Callback identity and range observations precede Rust owner locks. Registration
//! borrows no operation; only the outer ordinary caller can enter its paid stable
//! holder. Physical end returns that holder without replaying semantic time.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

/// Names the opaque native-issued ordinary retirement borrower.
#[repr(C)]
pub(crate) struct FingerprintLoan {
    _private: [u8; 0],
}

/// Distinguishes historical deferred obligations from the actual current capture.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct FingerprintStatus {
    pub(crate) schema_version: u32,
    pub(crate) struct_size: u32,
    pub(crate) publication_capture_generation: u64,
    pub(crate) publication_dirty_generation: u64,
    pub(crate) operation_capture_generation: u64,
    pub(crate) topology_generation: u64,
    pub(crate) dirty_generation: u64,
    pub(crate) region_count: u32,
    pub(crate) has_deferred_obligations: u32,
    pub(crate) first_status: i32,
    pub(crate) post_status: i32,
    pub(crate) deferred_first_status: i32,
    pub(crate) deferred_post_status: i32,
}

#[repr(C)]
#[derive(Default)]
struct CaptureContext {
    schema_version: u32,
    struct_size: u32,
    observation_only: u32,
}

#[repr(C)]
#[derive(Default, PartialEq, Eq)]
pub(crate) struct FingerprintReturnStatus {
    schema_version: u32,
    struct_size: u32,
    pub(crate) operation_capture_generation: u64,
    pub(crate) module_borrow_retained: u32,
    pub(crate) selector_returned: u32,
    pub(crate) first_status: i32,
    pub(crate) post_status: i32,
    pub(crate) return_status: i32,
}

type ContextObserve = extern "C" fn(u64, *mut CaptureContext) -> i32;
type ReturnObserve =
    extern "C" fn(u64, *mut *mut FingerprintLoan, *mut FingerprintReturnStatus) -> i32;

type Borrow = extern "C" fn(u64, *mut FingerprintLoan, *mut *mut c_void, *mut c_void) -> i32;
type Operation = extern "C" fn(u64, *mut FingerprintLoan, *mut c_void, *mut c_void) -> i32;
type Register = extern "C" fn(
    u64,
    Option<Borrow>,
    Option<Operation>,
    Option<Operation>,
    Option<Borrow>,
    *mut c_void,
) -> i32;
type Observe = extern "C" fn(u64, *mut FingerprintLoan, *mut FingerprintStatus) -> i32;
type Region = extern "C" fn(
    u64,
    *mut FingerprintLoan,
    u32,
    *mut crate::ram_fingerprint::CaptureRegion,
    *mut u64,
    *mut u64,
) -> i32;

#[derive(Clone, Copy)]
pub(crate) struct FingerprintApi {
    register: Register,
    observe: Observe,
    region: Region,
    context_observe: ContextObserve,
    return_observe: ReturnObserve,
    return_owner: ReturnObserve,
}

impl FingerprintApi {
    /// Observes real saved-Source invocation facts before any fresh clock.
    ///
    /// # Errors
    /// Refuses unauthenticated context or malformed current native output.
    pub(crate) fn observation_context(self, id: u64) -> Result<bool, RamError> {
        let mut context = CaptureContext::default();
        let status = (self.context_observe)(id, &mut context);
        native_status(status, "observe fingerprint invocation context")?;
        if context.schema_version != 1
            || context.struct_size as usize != std::mem::size_of::<CaptureContext>()
            || context.observation_only > 1
        {
            return Err(RamError::Invariant(
                "invalid fingerprint invocation context",
            ));
        }
        Ok(context.observation_only == 1)
    }

    /// Lends only the actual Source's old physical-return selector.
    ///
    /// # Errors
    /// Preserves native identity refusal; ENOENT reports absence, never reuse.
    pub(crate) fn old_borrow(self, id: u64) -> Result<Option<FingerprintReturn>, RamError> {
        let mut selector = std::ptr::null_mut();
        let mut status = FingerprintReturnStatus::default();
        let result = (self.return_observe)(id, &mut selector, &mut status);
        if result == -libc::ENOENT {
            if !selector.is_null() || status != FingerprintReturnStatus::default() {
                return Err(RamError::Invariant(
                    "native fingerprint absence modified the output loan",
                ));
            }
            return Ok(None);
        }
        native_status(result, "observe retained fingerprint borrower")?;
        status.validate()?;
        if selector.is_null() || status.module_borrow_retained != 1 || status.selector_returned != 0
        {
            return Err(RamError::Invariant(
                "native fingerprint borrower selector disagrees",
            ));
        }
        Ok(Some(FingerprintReturn {
            api: self,
            id,
            selector,
            status,
            disposition: None,
        }))
    }

    pub(crate) fn resolve() -> Result<Self, i32> {
        macro_rules! resolve {
            ($name:literal, $signature:ty) => {{
                // SAFETY: these literal functions/layouts are defined in the complete
                // matched Source SDK; resolution itself issues no operation loan.
                let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
                if address.is_null() {
                    return Err(-libc::ENOSYS);
                }
                // SAFETY: this exact nonnull symbol has the matched declaration.
                unsafe { std::mem::transmute::<*mut c_void, $signature>(address) }
            }};
        }
        Ok(Self {
            context_observe: resolve!(
                c"qemu_plugin_crucible_ram_capture_context_observe_v1",
                ContextObserve
            ),
            return_observe: resolve!(
                c"qemu_plugin_crucible_fingerprint_retirement_return_observe_v1",
                ReturnObserve
            ),
            return_owner: resolve!(
                c"qemu_plugin_crucible_fingerprint_retirement_return_v1",
                ReturnObserve
            ),
            register: resolve!(
                c"qemu_plugin_crucible_register_fingerprint_retirement_v1",
                Register
            ),
            observe: resolve!(
                c"qemu_plugin_crucible_fingerprint_retirement_observe_v2",
                Observe
            ),
            region: resolve!(
                c"qemu_plugin_crucible_fingerprint_retirement_region_v1",
                Region
            ),
        })
    }

    pub(super) fn register(self, id: u64, userdata: *mut c_void) -> Result<(), i32> {
        let status = (self.register)(
            id,
            Some(borrow),
            Some(rearm),
            Some(check),
            Some(end),
            userdata,
        );
        if status == 0 {
            Ok(())
        } else {
            Err(if status < 0 { status } else { -libc::EPROTO })
        }
    }
}

impl FingerprintReturnStatus {
    fn validate(&self) -> Result<(), RamError> {
        if self.schema_version != 1
            || self.struct_size as usize != std::mem::size_of::<Self>()
            || self.module_borrow_retained > 1
            || self.selector_returned > 1
            || self.first_status > 0
            || self.post_status > 0
            || self.return_status > 0
        {
            return Err(RamError::Invariant(
                "invalid native fingerprint physical return journal",
            ));
        }
        Ok(())
    }
}

/// Keeps the actual observed selector slot through its one identity-only attempt.
pub(crate) struct FingerprintReturn {
    api: FingerprintApi,
    id: u64,
    selector: *mut FingerprintLoan,
    pub(crate) status: FingerprintReturnStatus,
    disposition: Option<ValidatedFingerprintReturn>,
}

/// Validates one physical journal without granting Source or operation authority.
struct ValidatedFingerprintReturn {
    consumed: bool,
}

impl ValidatedFingerprintReturn {
    fn from_actual_return(
        journal: &FingerprintReturnStatus,
        expected_generation: u64,
        signed_result: i32,
        selector_is_null: bool,
    ) -> Result<Self, RamError> {
        journal.validate()?;
        if journal.operation_capture_generation != expected_generation
            || signed_result > 0
            || journal.return_status != signed_result
            || journal.module_borrow_retained + journal.selector_returned != 1
            || selector_is_null != (journal.selector_returned == 1)
        {
            return Err(RamError::Invariant(
                "fingerprint physical return disposition disagrees",
            ));
        }
        Ok(Self {
            consumed: selector_is_null,
        })
    }
}

impl FingerprintReturn {
    pub(crate) fn key(&self) -> usize {
        self.selector as usize
    }

    /// Invokes only old physical end and records consumption before signed status.
    ///
    /// # Errors
    /// Retains nonnull uncertainty or malformed native physical-return output.
    pub(crate) fn return_old(&mut self) -> Result<(), RamError> {
        self.disposition = None;
        let expected_generation = self.status.operation_capture_generation;
        let result = (self.api.return_owner)(self.id, &mut self.selector, &mut self.status);
        // Preserve the actual consumed pointer even if its journal is invalid.
        // Only a validated same-attempt disposition can return admission.
        self.disposition = Some(ValidatedFingerprintReturn::from_actual_return(
            &self.status,
            expected_generation,
            result,
            self.selector.is_null(),
        )?);
        native_status(result, "return retained fingerprint borrower")
    }

    pub(crate) fn consumed(&self) -> bool {
        self.selector.is_null()
            && self
                .disposition
                .as_ref()
                .is_some_and(|proof| proof.consumed)
    }
}

fn native_status(status: i32, operation: &'static str) -> Result<(), RamError> {
    if status == 0 {
        Ok(())
    } else {
        Err(RamError::Native {
            operation,
            status: if status < 0 { status } else { -libc::EPROTO },
        })
    }
}

/// Lends identity/ranges only through a genuine synchronous Source callback.
pub(crate) struct FingerprintBorrowContext {
    api: FingerprintApi,
    id: u64,
    loan: usize,
    pub(crate) status: FingerprintStatus,
}

impl FingerprintBorrowContext {
    /// Returns a rejection-only identity for this synchronous issued borrower.
    pub(crate) fn key(&self) -> usize {
        self.loan
    }

    /// Observes actual native ranges with every Rust owner guard released.
    ///
    /// # Errors
    /// Preserves native observation refusal or incompatible retained lineage.
    pub(crate) fn validate_baseline(
        &self,
        baseline: &crate::ram_fingerprint::FingerprintBaseline,
    ) -> Result<(), RamError> {
        baseline.validate_publication(
            self.status.publication_capture_generation,
            self.status.topology_generation,
        )?;
        if baseline
            .region_count()
            .is_some_and(|count| count != self.status.region_count as usize)
        {
            return Err(RamError::Invariant(
                "fingerprint loan inventory count changed",
            ));
        }
        for index in 0..self.status.region_count {
            let mut region = crate::ram_fingerprint::CaptureRegion::default();
            let mut start = 0;
            let mut end = 0;
            let status = (self.api.region)(
                self.id,
                self.loan as *mut FingerprintLoan,
                index,
                &mut region,
                &mut start,
                &mut end,
            );
            if status != 0 {
                return Err(RamError::Native {
                    operation: "borrow fingerprint captured range",
                    status: if status < 0 { status } else { -libc::EPROTO },
                });
            }
            baseline.validate_region(index as usize, &region, start, end)?;
        }
        Ok(())
    }
}

fn invoke(
    id: u64,
    loan: *mut FingerprintLoan,
    userdata: *mut c_void,
    callback: impl FnOnce(&FingerprintBorrowContext) -> i32,
) -> i32 {
    if loan.is_null() || userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: native retains the same pinned registered Runtime, and callback
    // entry occurs after installation. No borrow escapes this synchronous call.
    let runtime = unsafe { &*userdata.cast::<OwnedCallbackRuntimeState>() };
    if runtime.plugin_id != Some(id) || runtime.owner_process != std::process::id() {
        return -libc::ESTALE;
    }
    let Some(api) = runtime.checkpoint_api.map(|api| api.fingerprint) else {
        return -libc::ENOSYS;
    };
    let mut status = FingerprintStatus::default();
    let observed = (api.observe)(id, loan, &mut status);
    if observed != 0 {
        return if observed < 0 {
            observed
        } else {
            -libc::EPROTO
        };
    }
    if status.schema_version != 2
        || status.struct_size as usize != std::mem::size_of::<FingerprintStatus>()
        || status.topology_generation == 0
        || status.dirty_generation == 0
        || status.region_count == 0
        || status.region_count > 4096
        || status.first_status > 0
        || status.post_status > 0
        || status.has_deferred_obligations > 1
        || status.deferred_first_status > 0
        || status.deferred_post_status > 0
    {
        return -libc::EPROTO;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        callback(&FingerprintBorrowContext {
            api,
            id,
            loan: loan as usize,
            status,
        })
    }))
    .unwrap_or(-libc::EIO)
}

extern "C" fn borrow(
    id: u64,
    loan: *mut FingerprintLoan,
    output: *mut *mut c_void,
    userdata: *mut c_void,
) -> i32 {
    if output.is_null() {
        return -libc::EINVAL;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        invoke(id, loan, userdata, |context| {
            crate::paged_ram::controller::borrow_fingerprint(context, id, userdata, output)
        })
    }))
    .unwrap_or(-libc::EIO)
}

extern "C" fn rearm(
    id: u64,
    loan: *mut FingerprintLoan,
    owner: *mut c_void,
    userdata: *mut c_void,
) -> i32 {
    invoke(id, loan, userdata, |context| {
        crate::paged_ram::controller::rearm_fingerprint(context, id, userdata, owner)
    })
}

extern "C" fn check(
    id: u64,
    loan: *mut FingerprintLoan,
    owner: *mut c_void,
    userdata: *mut c_void,
) -> i32 {
    invoke(id, loan, userdata, |context| {
        crate::paged_ram::controller::check_fingerprint(context, id, userdata, owner)
    })
}

extern "C" fn end(
    id: u64,
    loan: *mut FingerprintLoan,
    owner: *mut *mut c_void,
    userdata: *mut c_void,
) -> i32 {
    if owner.is_null() {
        return -libc::EINVAL;
    }
    invoke(id, loan, userdata, |context| {
        crate::paged_ram::controller::end_fingerprint(context, id, userdata, owner)
    })
}

#[cfg(test)]
mod return_tests {
    use super::*;

    fn returned_journal() -> FingerprintReturnStatus {
        FingerprintReturnStatus {
            schema_version: 1,
            struct_size: std::mem::size_of::<FingerprintReturnStatus>() as u32,
            operation_capture_generation: 17,
            module_borrow_retained: 0,
            selector_returned: 1,
            first_status: -libc::ESTALE,
            post_status: -libc::ETIMEDOUT,
            return_status: -libc::EIO,
        }
    }

    #[test]
    fn consumed_output_requires_a_valid_same_attempt_journal() {
        for field in 0..8 {
            let mut journal = returned_journal();
            match field {
                0 => journal.schema_version = 2,
                1 => journal.struct_size = 0,
                2 => journal.operation_capture_generation += 1,
                3 => journal.module_borrow_retained = 1,
                4 => journal.selector_returned = 0,
                5 => journal.first_status = 1,
                6 => journal.post_status = 1,
                _ => journal.return_status = 1,
            }

            let disposition =
                ValidatedFingerprintReturn::from_actual_return(&journal, 17, -libc::EIO, true);

            assert!(disposition.is_err());
        }
    }

    #[test]
    fn signed_failure_does_not_hide_a_valid_consumed_disposition() {
        let journal = returned_journal();

        let disposition =
            ValidatedFingerprintReturn::from_actual_return(&journal, 17, -libc::EIO, true).unwrap();

        assert!(disposition.consumed);
        assert_eq!(journal.first_status, -libc::ESTALE);
        assert_eq!(journal.post_status, -libc::ETIMEDOUT);
        assert!(ValidatedFingerprintReturn::from_actual_return(&journal, 17, 1, true,).is_err());
        assert!(
            ValidatedFingerprintReturn::from_actual_return(&journal, 17, -libc::EIO, false,)
                .is_err()
        );
    }
}
