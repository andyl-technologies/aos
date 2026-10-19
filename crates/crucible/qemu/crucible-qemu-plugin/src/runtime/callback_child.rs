//! Retains Source's actual callback-child allocation and canonical field.
//!
//! Typed construction occurs inside Source's entered initializer/destructor.
//! Typed preparation borrows the actual family publication span; identity
//! observation lends journals only. Actual Native callback binding still gates
//! publication. Failed births and loans remain under the same pinned Runtime.
// SPDX-License-Identifier: GPL-2.0-only

use super::command_storage::NativeStorage as BridgeStorage;
use super::live_callbacks::LiveVcpuTimeCallbackError;
use crate::StartupSourceError;
use crate::startup_source::runtime_purpose::{CallbackChildClaim, RuntimePurpose};
use std::cell::UnsafeCell;
use std::mem::MaybeUninit;

mod abi;
mod placement;
mod publication;
pub(super) use abi::Storage as NativeStorage;
use abi::{Api, Status, Storage};
pub(super) use placement::{EnteredAllocation, Progress};

/// Lives inline in the prepriced pinned Runtime before its field can escape.
/// Native alone accesses holder contents under its registry mutex. Rust uses
/// distinct local projections and never reads that concurrently retained field.
pub(super) struct CallbackChild {
    holder: UnsafeCell<*mut Storage>,
    projection: *mut Storage,
    api: Option<Api>,
    id: u64,
    attempted: bool,
    transfer_attempted: bool,
    returned: bool,
    publication: publication::Publication,
}

impl CallbackChild {
    pub(super) const fn new() -> Self {
        Self {
            holder: UnsafeCell::new(std::ptr::null_mut()),
            projection: std::ptr::null_mut(),
            api: None,
            id: 0,
            attempted: false,
            transfer_attempted: false,
            returned: false,
            publication: publication::Publication::new(),
        }
    }

    /// Creates, initializes and transfers the genuine child once.
    ///
    /// # Errors
    /// Retains every born output before allocation, constructor or post refusal.
    /// No typed child projection or callback permission escapes this operation.
    ///
    /// # Safety
    /// This owner is already inside the paid pinned Runtime. That Runtime and
    /// the authentic Bridge parent stay live through all Native last-use cuts.
    pub(super) unsafe fn create<F>(
        &mut self,
        material: (u64, *mut RuntimePurpose, *mut CallbackChildClaim),
        bridge: *mut BridgeStorage,
        constructor: F,
    ) -> Result<(), LiveVcpuTimeCallbackError>
    where
        F: FnOnce(
            &mut MaybeUninit<super::live_callbacks::LiveVcpuTimeCallbackState>,
            Progress,
        ) -> Result<(), LiveVcpuTimeCallbackError>,
    {
        let api = Api::resolve().map_err(source_error)?;
        self.create_using(material, bridge, constructor, api)
    }

    fn create_using<F>(
        &mut self,
        material: (u64, *mut RuntimePurpose, *mut CallbackChildClaim),
        bridge: *mut BridgeStorage,
        constructor: F,
        api: Api,
    ) -> Result<(), LiveVcpuTimeCallbackError>
    where
        F: FnOnce(
            &mut MaybeUninit<super::live_callbacks::LiveVcpuTimeCallbackState>,
            Progress,
        ) -> Result<(), LiveVcpuTimeCallbackError>,
    {
        if self.attempted {
            return Err(status_error(-libc::EALREADY));
        }
        let (id, runtime, claim) = material;
        self.attempted = true;
        self.api = Some(api);
        self.id = id;
        let status = (api.create)(id, runtime, claim, bridge, &mut self.projection);
        // This field is the durable movable projection of Source's canonical
        // creation custody. A negative result can follow actual allocation.
        native_status(status)?;
        if self.projection.is_null() {
            return Err(status_error(-libc::EPROTO));
        }
        placement::initialize(id, self.projection, bridge, api, constructor)?;
        native_status((api.current)(id, self.projection))?;
        self.transfer_attempted = true;
        let storage = self.projection;
        let status = (api.transfer)(id, runtime, &mut self.projection, self.holder.get());
        let mut journal = Status::default();
        let observed = (api.observe)(id, storage, &mut journal);
        // Observe after the real move, before handling its signed post. Never
        // lose a negative canonical destination or substitute a raw field read.
        native_status(status)?;
        native_status(observed)?;
        if journal.schema_version != 1
            || journal.struct_size as usize != size_of::<Status>()
            || journal.transferred != 1
            || !self.projection.is_null()
        {
            return Err(status_error(-libc::EPROTO));
        }
        Ok(())
    }

    pub(super) fn retains_storage(&self) -> bool {
        self.attempted && !self.returned
    }

    /// Returns identity-only custody after the real caller proves no users.
    /// Refusal or ambiguous disposition retains the child and its Bridge parent.
    pub(super) fn identity_return(&mut self) -> bool {
        if self.publication.identity_return().is_err() {
            return false;
        }
        if self.returned {
            return true;
        }
        let Some(api) = self.api else {
            return true;
        };
        let canonical = self.projection.is_null() && self.transfer_attempted;
        let holder = if canonical {
            let mut projected = std::ptr::null_mut();
            if (api.holder_observe)(self.id, self.holder.get(), &mut projected) != 0
                || projected.is_null()
            {
                return false;
            }
            self.holder.get()
        } else if !self.projection.is_null() {
            &mut self.projection
        } else {
            return !self.attempted;
        };
        if (api.return_storage)(self.id, holder) != 0 {
            return false;
        }
        // The matched Source return authenticates and consumes its actual
        // canonical field only after physical completion. Its getter refuses
        // after retirement; do not invent a successful post-return getter or
        // read the foreign UnsafeCell. A movable local projection must be null.
        self.returned = canonical || self.projection.is_null();
        self.returned
    }

    /// Observes the actual retained canonical child for nominal owner creation.
    ///
    /// # Errors
    /// Refuses absent/retired/untransferred field custody. This opaque projection
    /// lends no typed body; Source's owner constructor authenticates it again.
    pub(super) fn nominal_storage(&self) -> Result<*mut Storage, LiveVcpuTimeCallbackError> {
        let api = self.api.ok_or_else(|| status_error(-libc::ESTALE))?;
        if !self.transfer_attempted || !self.projection.is_null() || self.returned {
            return Err(status_error(-libc::ESTALE));
        }
        let mut child = std::ptr::null_mut();
        native_status((api.holder_observe)(self.id, self.holder.get(), &mut child))?;
        if child.is_null() {
            return Err(status_error(-libc::ESTALE));
        }
        Ok(child)
    }

    /// Closes only the actual publication serial before parent identity cleanup.
    ///
    /// # Errors
    /// Retains refused or ambiguous span disposition; no child is destroyed here.
    pub(super) fn close_publication(&mut self) -> Result<(), LiveVcpuTimeCallbackError> {
        self.publication.identity_return()
    }

    /// Prepares the initialized child under its actual family span loan.
    ///
    /// # Errors
    /// Preserves genuine loan, typed preparation and physical return failures.
    ///
    /// # Safety
    /// The containing Runtime is paid/pinned and the closure exposes no child
    /// reference beyond the serial. An address may be passed only to the real
    /// Source component constructor, which independently retains this nominal
    /// child through its registration owner before saving any born output.
    pub(super) unsafe fn prepare_publication<F>(
        &mut self,
        preparation: F,
    ) -> Result<(), LiveVcpuTimeCallbackError>
    where
        F: FnOnce(
            &mut super::live_callbacks::LiveVcpuTimeCallbackState,
        ) -> Result<(), LiveVcpuTimeCallbackError>,
    {
        let child = self.nominal_storage()?;
        // SAFETY: the exact getter authenticated this retained canonical field;
        // prepare requires a separate genuine successful loan before typed access.
        unsafe { self.publication.prepare(self.id, child, preparation) }
    }

    /// Refuses callback execution when only physical registration was issued.
    pub(super) fn activation_unavailable() -> LiveVcpuTimeCallbackError {
        source_error(StartupSourceError::Ownership {
            reason: "callback-child execution activation and CPU use issuer are not issued",
        })
    }
}

fn source_error(source: StartupSourceError) -> LiveVcpuTimeCallbackError {
    LiveVcpuTimeCallbackError::CallbackChildStorage { source }
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
