//! Resolves the private RAM capture ABI and returns native dirty claims.
//!
//! Symbol resolution checks the capture interface before observer registration.
//! Each claim retains its native generation through commit or one noACK close;
//! cleanup refusal preserves native custody independently of logical cache state.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

/// Keeps the matched synchronous capture and observer entry points.
#[derive(Clone, Copy)]
pub(super) struct NativeApis {
    pub(super) begin: BeginCapture,
    pub(super) region: CaptureReadRegion,
    pub(super) next: NextPage,
    pub(super) finish: FinishCapture,
    pub(super) observation_only: ObservationOnly,
    pub(super) register: RegisterObserver,
    pub(super) register_record: RegisterRecordObserver,
    pub(super) register_transaction: RegisterTransactionObserver,
    pub(super) admission_region: ReadRegion,
    pub(super) register_admission: RegisterAdmissionObserver,
}

impl NativeApis {
    /// Resolves every required capture and registration export.
    ///
    /// # Errors
    /// Returns the missing symbol without issuing a capture or observer loan.
    pub(super) fn resolve() -> Result<Self, RamError> {
        // SAFETY: these symbols belong to the versioned GPL-private ABI, whose
        // native declarations have precisely the repr(C) layouts in the parent module. All
        // borrowed output pointers expire before each synchronous call returns.
        unsafe {
            Ok(Self {
                begin: std::mem::transmute::<*mut c_void, BeginCapture>(symbol(
                    b"qemu_plugin_crucible_ram_capture_begin_v2\0",
                )?),
                region: std::mem::transmute::<*mut c_void, CaptureReadRegion>(symbol(
                    b"qemu_plugin_crucible_ram_capture_region_v2\0",
                )?),
                next: std::mem::transmute::<*mut c_void, NextPage>(symbol(
                    b"qemu_plugin_crucible_ram_capture_next_page_v2\0",
                )?),
                finish: std::mem::transmute::<*mut c_void, FinishCapture>(symbol(
                    b"qemu_plugin_crucible_ram_capture_finish_v2\0",
                )?),
                observation_only: std::mem::transmute::<*mut c_void, ObservationOnly>(symbol(
                    b"qemu_plugin_crucible_ram_capture_observation_only_v1\0",
                )?),
                register: std::mem::transmute::<*mut c_void, RegisterObserver>(symbol(
                    b"qemu_plugin_crucible_register_ram_root_observer_v2\0",
                )?),
                register_record: std::mem::transmute::<*mut c_void, RegisterRecordObserver>(
                    symbol(b"qemu_plugin_crucible_register_ram_root_record_observer_v1\0")?,
                ),
                register_transaction: std::mem::transmute::<*mut c_void, RegisterTransactionObserver>(
                    symbol(b"qemu_plugin_crucible_register_ram_root_transaction_v1\0")?,
                ),
                admission_region: std::mem::transmute::<*mut c_void, ReadRegion>(symbol(
                    b"qemu_plugin_crucible_ram_admission_region_v1\0",
                )?),
                register_admission: std::mem::transmute::<*mut c_void, RegisterAdmissionObserver>(
                    symbol(b"qemu_plugin_crucible_register_ram_admission_v1\0")?,
                ),
            })
        }
    }
}

/// Resolves a static private export name without issuing native authority.
///
/// # Errors
/// Returns the missing symbol when the matching interface is unavailable.
pub(super) fn symbol(name: &'static [u8]) -> Result<*mut c_void, RamError> {
    // SAFETY: every caller supplies a static NUL-terminated symbol name.
    let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr().cast()) };
    if address.is_null() {
        return Err(RamError::MissingSymbol(name));
    }
    Ok(address)
}

/// Retains a dirty claim through commit or one noACK close attempt.
pub(super) struct CaptureClaim {
    pub(super) apis: NativeApis,
    pub(super) header: CaptureHeader,
    pub(super) owner_token: u64,
    pub(super) finished: bool,
}

impl CaptureClaim {
    /// Validates a newly opened capture claim.
    ///
    /// # Errors
    /// Preserves native begin refusal or invalid capture geometry.
    pub(super) fn begin(apis: NativeApis, full: bool, owner_token: u64) -> Result<Self, RamError> {
        let claim = Self::open(apis, full, owner_token)?;
        claim.validate_header()?;
        Ok(claim)
    }

    /// Opens the native claim before validating its returned header.
    ///
    /// # Errors
    /// Preserves a refused native begin without constructing a claim.
    pub(super) fn open(apis: NativeApis, full: bool, owner_token: u64) -> Result<Self, RamError> {
        let mut header = CaptureHeader::default();
        status(
            (apis.begin)(u32::from(full), owner_token, &mut header),
            "begin RAM capture",
        )?;
        Ok(Self {
            apis,
            header,
            owner_token,
            finished: false,
        })
    }

    /// Opens under the Original already entered by the native Root caller.
    pub(super) fn open_logical(
        apis: NativeApis,
        original: &original::Call<'_>,
        full: bool,
    ) -> Result<Self, RamError> {
        let header = original.begin(full, false)?;
        Ok(Self {
            apis,
            header,
            owner_token: 0,
            finished: false,
        })
    }

    /// Transfers old-capture cleanup to the native same-Original restart caller.
    pub(super) fn restart_logical(
        mut self,
        original: &original::Call<'_>,
    ) -> Result<Self, RamError> {
        let opened = original.begin(true, true);
        // The native restart owns the sole physical old-claim return attempt,
        // including refusal/nonconsumption. Never retry it via numeric Drop.
        self.finished = true;
        let header = opened?;
        Ok(Self {
            apis: self.apis,
            header,
            owner_token: 0,
            finished: false,
        })
    }

    /// Checks the current capture header against the private format.
    ///
    /// # Errors
    /// Refuses invalid schema, empty or oversized inventory, and zero identity.
    pub(super) fn validate_header(&self) -> Result<(), RamError> {
        if self.header.schema != CAPTURE_SCHEMA
            || self.header.region_count == 0
            || self.header.region_count as usize > MAX_REGIONS
            || self.header.topology_generation == 0
            || self.header.capture_generation == 0
            || self.header.metadata_budget_bytes == 0
        {
            return Err(RamError::Invariant("invalid native RAM capture header"));
        }
        Ok(())
    }

    /// Retires the fingerprint consumer and records its actual close.
    ///
    /// # Errors
    /// Preserves native finish refusal or a changed module close journal.
    pub(super) fn commit(mut self) -> Result<(), RamError> {
        status(
            (self.apis.finish)(self.header.capture_generation, self.owner_token, 1),
            "commit RAM capture",
        )?;
        self.finished = true;
        Ok(())
    }

    /// Attempts cleanup once without acknowledging dirty pages or rearming RAM.
    ///
    /// The returned status belongs to the sole cleanup attempt, so a prior
    /// failure can be retained separately from cleanup refusal. `None` means
    /// the claim was already committed or cleanup was attempted; it does not
    /// prove cleanup succeeded. A refusal leaves native custody intact.
    pub(super) fn close_without_ack(&mut self) -> Option<c_int> {
        if self.finished {
            return None;
        }
        let result = (self.apis.finish)(self.header.capture_generation, self.owner_token, 0);
        self.finished = true;
        Some(result)
    }
}

impl Drop for CaptureClaim {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.close_without_ack();
        }
    }
}
