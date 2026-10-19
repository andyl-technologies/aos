//! Retains Source's nominal completed-child registration owner.
//!
//! Creation and canonical transfer precede typed family preparation. The owner
//! keeps its true child/Bridge parents; nominal current is identity observation,
//! never callback activation, a usable child body or operation authority.
// SPDX-License-Identifier: GPL-2.0-only

use super::callback_child::NativeStorage;
use super::live_callbacks::LiveVcpuTimeCallbackError;
use crate::StartupSourceError;
use std::cell::UnsafeCell;

mod abi;
use abi::{Api, Owner};

/// Lives inline in the genuine whole Runtime Layout before reserve and birth.
/// Source alone reads/writes the stable canonical field under its registry mutex;
/// Rust retains separate projections and never borrows that field's pointee.
pub(super) struct RegistrationOwner {
    holder: UnsafeCell<*mut Owner>,
    creation: *mut Owner,
    observed: *mut Owner,
    api: Option<Api>,
    id: u64,
    attempted: bool,
    transfer_attempted: bool,
    returned: bool,
}

impl RegistrationOwner {
    pub(super) const fn new() -> Self {
        Self {
            holder: UnsafeCell::new(std::ptr::null_mut()),
            creation: std::ptr::null_mut(),
            observed: std::ptr::null_mut(),
            api: None,
            id: 0,
            attempted: false,
            transfer_attempted: false,
            returned: false,
        }
    }

    /// Creates and transfers actual completed-child custody once.
    ///
    /// # Errors
    /// Retains every born projection and transferred canonical output before
    /// interpreting the first signed refusal. No family permission is issued.
    ///
    /// # Safety
    /// This keeper is already in the paid pinned Runtime; the child pointer is
    /// obtained from Source's protected canonical child-field getter.
    pub(super) unsafe fn create(
        &mut self,
        id: u64,
        child: *mut NativeStorage,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let api = Api::resolve().map_err(source_error)?;
        self.create_using(id, child, api)
    }

    fn create_using(
        &mut self,
        id: u64,
        child: *mut NativeStorage,
        api: Api,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        if self.attempted {
            return Err(status_error(-libc::EALREADY));
        }
        self.id = id;
        self.api = Some(api);
        self.attempted = true;
        let status = (api.create)(id, child, &mut self.creation);
        // Source owns its fixed creation field; this distinct movable output
        // remains observable even when the independent postcut refuses.
        if !self.creation.is_null() {
            self.observed = self.creation;
        }
        native_status(status)?;
        if self.creation.is_null() {
            return Err(status_error(-libc::EPROTO));
        }
        self.transfer_attempted = true;
        let status = (api.transfer)(id, &mut self.creation, self.holder.get());
        // The actual canonical destination is saved before Source consumes the
        // projection and runs its post. Do not read the foreign field in Rust.
        native_status(status)?;
        if !self.creation.is_null() {
            return Err(status_error(-libc::EPROTO));
        }
        self.current()
    }

    /// Observes the same actual transferred nominal owner without new permission.
    ///
    /// # Errors
    /// Refuses missing/negative/incomplete or retired custody and parent work.
    pub(super) fn current(&self) -> Result<(), LiveVcpuTimeCallbackError> {
        let api = self.api.ok_or_else(|| status_error(-libc::ESTALE))?;
        if !self.transfer_attempted
            || !self.creation.is_null()
            || self.observed.is_null()
            || self.returned
        {
            return Err(status_error(-libc::ESTALE));
        }
        native_status((api.current)(self.id, self.observed))
    }

    /// Returns only the checked nominal owner for Source's worker constructor.
    ///
    /// # Errors
    /// Refuses absent or stale canonical custody; this lends no typed child.
    pub(super) fn native_projection(
        &self,
    ) -> Result<*mut std::ffi::c_void, LiveVcpuTimeCallbackError> {
        self.current()?;
        Ok(self.observed.cast())
    }

    pub(super) fn retained(&self) -> bool {
        self.attempted && !self.returned
    }

    /// Returns only actual Source custody after independent dependency settlement.
    ///
    /// # Errors
    /// Preserves live component/publication/registrar debt and ambiguous disposition.
    /// Identity return supplies no callback termination or resource refund witness.
    pub(super) fn identity_return(&mut self) -> Result<(), LiveVcpuTimeCallbackError> {
        if self.returned || !self.attempted {
            return Ok(());
        }
        let api = self.api.ok_or_else(|| status_error(-libc::ESTALE))?;
        let canonical = self.transfer_attempted && self.creation.is_null();
        let holder = if canonical {
            self.holder.get()
        } else if !self.creation.is_null() {
            &mut self.creation
        } else {
            // No output was supplied: no successful return is inferred from a
            // negative constructor status. Containing custody stays retained.
            return Err(status_error(-libc::ESTALE));
        };
        native_status((api.return_owner)(self.id, holder))?;
        if !canonical && !self.creation.is_null() {
            return Err(status_error(-libc::EPROTO));
        }
        // The actual protected return consumes the exact canonical field on0.
        // It has no post-return getter; don't read the foreign UnsafeCell.
        self.observed = std::ptr::null_mut();
        self.returned = true;
        Ok(())
    }
}

fn source_error(source: StartupSourceError) -> LiveVcpuTimeCallbackError {
    LiveVcpuTimeCallbackError::CallbackRegistrationOwner { source }
}

fn status_error(status: i32) -> LiveVcpuTimeCallbackError {
    source_error(StartupSourceError::NativeStatus { status })
}

fn native_status(status: i32) -> Result<(), LiveVcpuTimeCallbackError> {
    if status == 0 {
        Ok(())
    } else {
        Err(status_error(status))
    }
}

#[cfg(test)]
mod tests;
