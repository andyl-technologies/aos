//! Retains Source's physical workspace mapping inside the prepaid Runtime.
//!
//! Source alone accesses the stable canonical field. Constructor outputs and
//! each signed result survive negative posts; neither a pointer nor current
//! lends mutable bytes, a worker Original or material retirement authority.
// SPDX-License-Identifier: GPL-2.0-only

use crate::DeviceDigestWorkspaceError;
use crate::startup_source::runtime_purpose::RuntimePurpose;
use std::cell::UnsafeCell;
use std::ffi::c_void;

mod abi;
use abi::{Api, Mapping};

/// Belongs to request0's complete Runtime Layout before reserve and allocation.
pub(super) struct WorkspaceMapping {
    holder: UnsafeCell<*mut Mapping>,
    creation: *mut Mapping,
    observed: *mut Mapping,
    address: *mut c_void,
    extent: usize,
    api: Option<Api>,
    id: u64,
    process: u32,
    attempted: bool,
    transfer_attempted: bool,
    returned: bool,
    inherited_disarmed: bool,
    creation_status: Option<i32>,
    transfer_status: Option<i32>,
    current_status: Option<i32>,
    return_status: Option<i32>,
}

impl WorkspaceMapping {
    pub(super) const fn new() -> Self {
        Self {
            holder: UnsafeCell::new(std::ptr::null_mut()),
            creation: std::ptr::null_mut(),
            observed: std::ptr::null_mut(),
            address: std::ptr::null_mut(),
            extent: 0,
            api: None,
            id: 0,
            process: 0,
            attempted: false,
            transfer_attempted: false,
            returned: false,
            inherited_disarmed: false,
            creation_status: None,
            transfer_status: None,
            current_status: None,
            return_status: None,
        }
    }

    /// Creates and transfers the actual optional role's VMA to this fixed field.
    ///
    /// # Safety
    /// This keeper is in the paid pinned Runtime. The genuine same Runtime's
    /// child and nominal registration owner have completed their transfers.
    ///
    /// # Errors
    /// Retains constructor outputs and moved canonical ownership before any
    /// initiating/post refusal. No mapping operation is replayed on failure.
    pub(super) unsafe fn create(
        &mut self,
        id: u64,
        runtime: *mut RuntimePurpose,
    ) -> Result<(), DeviceDigestWorkspaceError> {
        let api = Api::resolve().map_err(source_error)?;
        self.create_using(id, runtime, api)
    }

    fn create_using(
        &mut self,
        id: u64,
        runtime: *mut RuntimePurpose,
        api: Api,
    ) -> Result<(), DeviceDigestWorkspaceError> {
        if self.attempted || runtime.is_null() {
            return Err(ownership_error(
                "workspace construction is repeated or lacks its Runtime",
            ));
        }
        self.api = Some(api);
        self.id = id;
        self.process = std::process::id();
        self.attempted = true;
        let status = (api.create)(id, &mut self.creation, &mut self.address, &mut self.extent);
        self.creation_status = Some(status);
        self.observed = self.creation;
        native_status(status)?;
        if self.creation.is_null()
            || self.address.is_null()
            || self.extent != crucible_qemu_protocol::DEVICE_DIGEST_WORKSPACE_BYTES as usize
        {
            return Err(ownership_error(
                "Source workspace constructor outputs differ",
            ));
        }
        self.transfer_attempted = true;
        let status = (api.transfer)(id, runtime, &mut self.creation, self.holder.get());
        self.transfer_status = Some(status);
        // Source may already have moved its exact canonical field before a
        // negative post. Only this separate local projection is read by Rust.
        native_status(status)?;
        if !self.creation.is_null() {
            return Err(ownership_error(
                "Source workspace transfer left its creation projection",
            ));
        }
        self.current()
    }

    /// Corroborates physical custody without returning a byte view.
    ///
    /// # Errors
    /// Refuses inherited, absent, untransferred, negative or retired ownership.
    pub(super) fn current(&mut self) -> Result<(), DeviceDigestWorkspaceError> {
        self.same_process()?;
        if !self.transfer_attempted || !self.creation.is_null() || self.observed.is_null() {
            return Err(ownership_error(
                "workspace has no transferred physical owner",
            ));
        }
        if self.creation_status != Some(0) || self.transfer_status != Some(0) {
            return Err(ownership_error(
                "workspace construction retained a signed refusal",
            ));
        }
        let api = self
            .api
            .ok_or_else(|| ownership_error("workspace SDK is absent"))?;
        let status = (api.current)(self.id, self.observed);
        self.current_status = Some(status);
        native_status(status)
    }

    /// Returns only exact physical identity after Source's genuine last-use gate.
    ///
    /// # Errors
    /// Transferred worker/material debt currently refuses ENOKEY. Pretransfer
    /// cleanup can consume the creation projection even after a negative post.
    pub(super) fn identity_return(&mut self) -> Result<(), DeviceDigestWorkspaceError> {
        if !self.attempted || self.returned {
            return Ok(());
        }
        self.same_process()?;
        if self.creation_status.is_some_and(|status| status < 0)
            && !self.transfer_attempted
            && self.creation.is_null()
            && self.observed.is_null()
            && self.address.is_null()
            && self.extent == 0
        {
            // Source publishes its owner before effects. This exact negative
            // empty result created no mapping debt; the attempted birth and
            // signed refusal remain, so settling custody cannot replay it.
            self.returned = true;
            return Ok(());
        }
        let api = self
            .api
            .ok_or_else(|| ownership_error("workspace SDK is absent"))?;
        let canonical = self.transfer_attempted && self.creation.is_null();
        let holder = if canonical {
            self.holder.get()
        } else if !self.creation.is_null() {
            &mut self.creation
        } else {
            return Err(ownership_error(
                "workspace disposition lacks a retained projection",
            ));
        };
        let status = (api.identity_return)(self.id, holder);
        self.return_status = Some(status);
        native_status(status)?;
        if !canonical && !self.creation.is_null() {
            return Err(ownership_error(
                "Source did not consume its workspace projection",
            ));
        }
        // The genuine return consumes its canonical field on success. There is
        // no post-return getter and Rust never inspects that foreign field.
        self.returned = true;
        self.observed = std::ptr::null_mut();
        self.address = std::ptr::null_mut();
        self.extent = 0;
        Ok(())
    }

    /// Disarms only the child's copied local view before descriptor reuse.
    ///
    /// # Errors
    /// Refuses a parent call or repeated disarm. No inherited Source lock,
    /// canonical field, descriptor, mapping or return method is touched.
    pub(super) fn disarm_inherited(&mut self) -> Result<(), DeviceDigestWorkspaceError> {
        if !self.attempted {
            return Ok(());
        }
        if self.process == std::process::id() || self.inherited_disarmed {
            return Err(ownership_error(
                "workspace disarm is not a fresh child transition",
            ));
        }
        self.inherited_disarmed = true;
        self.address = std::ptr::null_mut();
        self.extent = 0;
        self.observed = std::ptr::null_mut();
        Ok(())
    }

    fn same_process(&self) -> Result<(), DeviceDigestWorkspaceError> {
        if self.process != std::process::id() || self.inherited_disarmed || self.returned {
            return Err(ownership_error(
                "workspace belongs to another or retired incarnation",
            ));
        }
        Ok(())
    }
}

fn source_error(source: crate::StartupSourceError) -> DeviceDigestWorkspaceError {
    DeviceDigestWorkspaceError::StartupSource { source }
}

fn native_status(status: i32) -> Result<(), DeviceDigestWorkspaceError> {
    if status == 0 {
        Ok(())
    } else {
        Err(DeviceDigestWorkspaceError::Admission { status })
    }
}

fn ownership_error(reason: &'static str) -> DeviceDigestWorkspaceError {
    DeviceDigestWorkspaceError::Ownership { reason }
}

#[cfg(test)]
mod tests;
