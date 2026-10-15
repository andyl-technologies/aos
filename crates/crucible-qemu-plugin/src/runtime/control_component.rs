//! Retains the Native control child through its exact durable Runtime field.
//!
//! Enrollment, factual projection, actual callback publication, and physical
//! identity return are independent cuts. A signed refusal never erases a born
//! field or releases its containing callback allocations.
// SPDX-License-Identifier: GPL-2.0-only

use std::cell::UnsafeCell;
use std::ffi::c_void;

use crate::ram_error::RamError;

use super::live_callbacks::ControlIntentFacts;

/// Names the genuine Source-owned enrolled control component.
#[repr(C)]
pub(super) struct NativeComponent {
    _private: [u8; 0],
}

/// Matches the creating control boundary callback's process-private signature.
pub(super) type ControlCallback = extern "C" fn(u32, u64, *mut c_void);
/// Matches the separate factual callback without semantic dispatch.
pub(super) type FactsCallback = extern "C" fn(*mut ControlIntentFacts, *mut c_void) -> i32;

type Enroll = extern "C" fn(
    u64,
    ControlCallback,
    *mut c_void,
    FactsCallback,
    *mut c_void,
    *mut *mut NativeComponent,
) -> i32;
type Observe = extern "C" fn(
    *mut *mut NativeComponent,
    ControlCallback,
    *mut c_void,
    *mut *mut NativeComponent,
) -> i32;
type Current = extern "C" fn(
    *mut *mut NativeComponent,
    *mut NativeComponent,
    ControlCallback,
    *mut c_void,
) -> i32;
type IdentityReturn = extern "C" fn(*mut *mut NativeComponent) -> i32;

#[derive(Clone, Copy)]
struct Api {
    enroll: Enroll,
    observe: Observe,
    current: Current,
    identity_return: IdentityReturn,
}

/// Owns the canonical output field inside the genuinely prepaid pinned Runtime.
/// Native alone accesses its pointee under the actual Source registry mutex;
/// the module observes only protected projections into distinct local outputs.
pub(super) struct ControlComponent {
    holder: UnsafeCell<*mut NativeComponent>,
    projection: *mut NativeComponent,
    api: Option<Api>,
    callback: Option<ControlCallback>,
    child_userdata: *mut c_void,
    owner_process: u32,
    attempted: bool,
    current_status: i32,
    return_status: i32,
    returned: bool,
}

impl ControlComponent {
    /// Initializes an unexposed field inside the already admitted Runtime body.
    pub(super) fn new() -> Self {
        Self {
            holder: UnsafeCell::new(std::ptr::null_mut()),
            projection: std::ptr::null_mut(),
            api: None,
            callback: None,
            child_userdata: std::ptr::null_mut(),
            owner_process: std::process::id(),
            attempted: false,
            current_status: 0,
            return_status: 0,
            returned: false,
        }
    }

    /// Enrolls the actual child before the existing Native callback registrar.
    ///
    /// # Errors
    /// Refuses absent exports, foreign/repeated use, or the original enrollment
    /// and observation statuses. Born fields and projections remain retained.
    pub(super) fn enroll(
        &mut self,
        plugin_id: u64,
        runtime_userdata: *mut c_void,
        callback: ControlCallback,
        child_userdata: *mut c_void,
        facts: FactsCallback,
    ) -> Result<(), RamError> {
        let api = resolve()?;
        self.enroll_using(
            api,
            plugin_id,
            runtime_userdata,
            callback,
            child_userdata,
            facts,
        )
    }

    fn enroll_using(
        &mut self,
        api: Api,
        plugin_id: u64,
        runtime_userdata: *mut c_void,
        callback: ControlCallback,
        child_userdata: *mut c_void,
        facts: FactsCallback,
    ) -> Result<(), RamError> {
        if self.owner_process != std::process::id()
            || self.attempted
            || runtime_userdata.is_null()
            || child_userdata.is_null()
            || runtime_userdata == child_userdata
        {
            return Err(RamError::Invariant(
                "control component owning relation differs",
            ));
        }
        self.api = Some(api);
        self.callback = Some(callback);
        self.child_userdata = child_userdata;
        self.attempted = true;

        // Native publishes directly into this durable field before its postcut.
        let first = (api.enroll)(
            plugin_id,
            callback,
            child_userdata,
            facts,
            runtime_userdata,
            self.holder.get(),
        );
        let mut projected = std::ptr::null_mut();
        let observation =
            (api.observe)(self.holder.get(), callback, child_userdata, &mut projected);
        if !projected.is_null() {
            self.projection = projected;
        }
        // The physical projection is retained before either signed result is
        // interpreted. It never replaces the canonical Native output field.
        status(first, "control component enrollment")?;
        status(observation, "control component observation")?;
        if self.projection.is_null() {
            return Err(RamError::Invariant(
                "control component output identity differs",
            ));
        }
        Ok(())
    }

    /// Obtains this same Source-owned component into a disjoint local projection.
    ///
    /// # Errors
    /// Refuses absent custody or genuine observation failure. The output lends
    /// no typed child body, callback activation or action Original.
    pub(super) fn nominal_projection(&self) -> Result<*mut NativeComponent, RamError> {
        let api = self
            .api
            .ok_or(RamError::Invariant("control component API absent"))?;
        let callback = self
            .callback
            .ok_or(RamError::Invariant("control callback absent"))?;
        if self.returned || self.owner_process != std::process::id() {
            return Err(RamError::Invariant("control component custody absent"));
        }
        let mut projection = std::ptr::null_mut();
        let observed = (api.observe)(
            self.holder.get(),
            callback,
            self.child_userdata,
            &mut projection,
        );
        status(observed, "control component projection")?;
        if projection.is_null() {
            return Err(RamError::Invariant("control component projection absent"));
        }
        Ok(projection)
    }

    /// Verifies actual publication after the void Native callback registrar.
    ///
    /// # Errors
    /// Refuses foreign/absent custody or actual Source/Native registration
    /// mismatch. A successful void registrar call alone supplies no proof.
    pub(super) fn verify_registered(&mut self) -> Result<(), RamError> {
        let api = self
            .api
            .ok_or(RamError::Invariant("control component API absent"))?;
        let callback = self
            .callback
            .ok_or(RamError::Invariant("control callback absent"))?;
        if self.owner_process != std::process::id() || self.returned || self.projection.is_null() {
            return Err(RamError::Invariant("control component custody absent"));
        }
        self.current_status = (api.current)(
            self.holder.get(),
            self.projection,
            callback,
            self.child_userdata,
        );
        status(self.current_status, "control component registration")
    }

    /// Returns only this same field after Native's actual detached-child proof.
    ///
    /// # Errors
    /// Preserves foreign or unavailable custody and the original return status.
    /// Actual field consumption remains distinct from that signed status. This
    /// method never detaches callbacks, ends an operation, or refunds storage.
    pub(super) fn identity_return(&mut self) -> Result<(), RamError> {
        if !self.attempted || self.returned {
            return Ok(());
        }
        if self.owner_process != std::process::id() {
            return Err(RamError::Invariant(
                "control component belongs to another process",
            ));
        }
        let api = self
            .api
            .ok_or(RamError::Invariant("control component API absent"))?;
        self.return_status = (api.identity_return)(self.holder.get());
        if self.return_status == 0 {
            // The matched protected Source return consumes this canonical field
            // only after the genuine detached/reader proof. Rust never reads the
            // concurrently Native-managed field or manufactures its disposition.
            self.projection = std::ptr::null_mut();
            self.returned = true;
        }
        status(self.return_status, "control component identity return")
    }
}

fn status(value: i32, operation: &'static str) -> Result<(), RamError> {
    if value == 0 {
        Ok(())
    } else {
        Err(RamError::Native {
            operation,
            status: value,
        })
    }
}

fn resolve() -> Result<Api, RamError> {
    macro_rules! export {
        ($name:literal, $signature:ty) => {{
            // SAFETY: this annotated export and exact signature belong to the
            // selected GPL-private SDK. Symbol presence issues no authority.
            let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
            if address.is_null() {
                return Err(RamError::MissingSymbol($name.to_bytes_with_nul()));
            }
            // SAFETY: the matched annotated C declaration has this signature.
            unsafe { std::mem::transmute::<*mut c_void, $signature>(address) }
        }};
    }
    Ok(Api {
        enroll: export!(c"qemu_plugin_crucible_control_component_enroll_v1", Enroll),
        observe: export!(
            c"qemu_plugin_crucible_control_component_observe_v1",
            Observe
        ),
        current: export!(
            c"qemu_plugin_crucible_control_component_current_v1",
            Current
        ),
        identity_return: export!(
            c"qemu_plugin_crucible_control_component_return_v1",
            IdentityReturn
        ),
    })
}
