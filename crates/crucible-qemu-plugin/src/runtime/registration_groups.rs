//! Retains complete physical registration groups inside the prepaid Runtime.
//!
//! Each actual registrar receives a fresh entered typed span. Source owns the
//! canonical group field, member storage and independent post receipt; span
//! return never retires Native registrations or enables callback execution.
// SPDX-License-Identifier: GPL-2.0-only

use super::callback_child::NativeStorage;
use super::live_callbacks::{LiveVcpuTimeCallbackError, LiveVcpuTimeCallbackState};
use crate::StartupSourceError;
use std::alloc::Layout;
use std::cell::UnsafeCell;
use std::ffi::c_void;

mod abi;
use abi::{Api, Owner, Status};

/// Matches the owning process-private C enum, including its three singleton cuts.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    IdleResume = 1,
    Dispatch = 2,
    NetTx = 3,
    Block = 4,
    BlockEvent = 5,
    BlockWait = 6,
    NineP = 7,
    Accelerator = 8,
    Control = 9,
    TimeAdvance = 10,
    VcpuInit = 11,
}

/// Keeps actual installation order separate from enum discriminants.
const INSTALLATION_ORDER: [Kind; 11] = [
    Kind::IdleResume,
    Kind::Control,
    Kind::Dispatch,
    Kind::TimeAdvance,
    Kind::NetTx,
    Kind::Block,
    Kind::BlockEvent,
    Kind::BlockWait,
    Kind::NineP,
    Kind::Accelerator,
    Kind::VcpuInit,
];

/// Adds no allocation; the full containing Runtime Layout prices every keeper.
pub(super) struct RegistrationGroups {
    groups: [Group; 11],
}

impl RegistrationGroups {
    pub(super) const fn new() -> Self {
        Self {
            groups: [const { Group::new() }; 11],
        }
    }

    /// Calls one actual registrar only within its genuine entered group span.
    ///
    /// # Errors
    /// Retains born outputs, partial effects and every refused/unknown return.
    ///
    /// # Safety
    /// The complete containing Runtime is already paid and pinned; child is an
    /// actual protected nominal Source projection. The registrar is the matching
    /// Native group effect, with its own preeffect member admission and receipts.
    pub(super) unsafe fn install(
        &mut self,
        id: u64,
        child: *mut NativeStorage,
        kind: Kind,
        registrar: impl FnOnce(&mut LiveVcpuTimeCallbackState) -> Result<(), LiveVcpuTimeCallbackError>,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let api = Api::resolve().map_err(source_error)?;
        let group = self
            .groups
            .get_mut(kind as usize - 1)
            .ok_or_else(|| status_error(-libc::EINVAL))?;
        group.install_using(id, child, kind, registrar, api)
    }

    /// Closes temporary spans without claiming any registration has retired.
    ///
    /// # Errors
    /// Preserves all group debt if any span has refused or unknown disposition.
    pub(super) fn close_spans(&mut self) -> Result<(), LiveVcpuTimeCallbackError> {
        let mut first = Ok(());
        for kind in INSTALLATION_ORDER.into_iter().rev() {
            let group = self
                .groups
                .get_mut(kind as usize - 1)
                .ok_or_else(|| status_error(-libc::EINVAL))?;
            let returned = group.close_span();
            first = first.and(returned);
        }
        first
    }

    /// Returns each true canonical owner only after its Native terminal proof.
    ///
    /// # Errors
    /// Keeps the containing graph if any physical owner or material user remains.
    pub(super) fn identity_return(&mut self) -> Result<(), LiveVcpuTimeCallbackError> {
        self.close_spans()?;
        let mut first = Ok(());
        for kind in INSTALLATION_ORDER.into_iter().rev() {
            let group = self
                .groups
                .get_mut(kind as usize - 1)
                .ok_or_else(|| status_error(-libc::EINVAL))?;
            let returned = group.identity_return();
            first = first.and(returned);
        }
        first
    }
}

#[derive(Clone, Copy)]
struct Span {
    address: *mut c_void,
    bytes: usize,
    alignment: usize,
}

impl Span {
    const fn empty() -> Self {
        Self {
            address: std::ptr::null_mut(),
            bytes: 0,
            alignment: 0,
        }
    }
}

struct Group {
    // Only Source accesses this canonical field, through its registry mutex.
    holder: UnsafeCell<*mut Owner>,
    creation: *mut Owner,
    projection: *mut Owner,
    serial: u64,
    observed_serial: u64,
    span: Span,
    journal: Option<Status>,
    api: Option<Api>,
    id: u64,
    kind: Option<Kind>,
    attempted: bool,
    transfer_attempted: bool,
    span_closed: bool,
    returned: bool,
    uncertain: bool,
}

impl Group {
    const fn new() -> Self {
        Self {
            holder: UnsafeCell::new(std::ptr::null_mut()),
            creation: std::ptr::null_mut(),
            projection: std::ptr::null_mut(),
            serial: 0,
            observed_serial: 0,
            span: Span::empty(),
            journal: None,
            api: None,
            id: 0,
            kind: None,
            attempted: false,
            transfer_attempted: false,
            span_closed: false,
            returned: false,
            uncertain: false,
        }
    }

    fn install_using(
        &mut self,
        id: u64,
        child: *mut NativeStorage,
        kind: Kind,
        registrar: impl FnOnce(&mut LiveVcpuTimeCallbackState) -> Result<(), LiveVcpuTimeCallbackError>,
        api: Api,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        if self.attempted {
            return Err(status_error(-libc::EALREADY));
        }
        self.id = id;
        self.kind = Some(kind);
        self.api = Some(api);
        self.attempted = true;
        let status = (api.begin)(id, child, kind, &mut self.creation, &mut self.serial);
        // Source's own creation field precedes these outputs and its post.
        // Never call another begin into this pair after a born-negative result.
        let entered = native_status(status).and_then(|()| {
            if self.creation.is_null() || self.serial == 0 {
                self.uncertain = true;
                return Err(status_error(-libc::EPROTO));
            }
            self.transfer_attempted = true;
            let status =
                (api.transfer)(id, &mut self.creation, self.serial, kind, self.holder.get());
            // Protected observation is attempted even after a negative move.
            let observed = self.observe_holder();
            native_status(status).and(observed)
        });
        let prepared = entered.and_then(|()| {
            native_status((api.current)(
                id,
                self.projection,
                self.serial,
                kind,
                &mut self.span.address,
                &mut self.span.bytes,
                &mut self.span.alignment,
            ))?;
            let layout = Layout::new::<LiveVcpuTimeCallbackState>();
            if self.span.address.is_null()
                || self.span.bytes != layout.size()
                || self.span.alignment != layout.align()
                || (self.span.address as usize) % layout.align() != 0
            {
                return Err(status_error(-libc::EPROTO));
            }
            // SAFETY: the actual successful Source current lends this complete
            // unique initialized span. The closure cannot return a borrowed
            // projection; Native's matching registrar independently authenticates
            // its member borrower before it retains any callback address.
            registrar(unsafe { &mut *self.span.address.cast::<LiveVcpuTimeCallbackState>() })
        });
        // This observes real partial/negative effects independently from the
        // registrar's initiating result, and before temporary span return.
        let receipt = if self.projection.is_null() {
            Ok(())
        } else {
            native_status((api.postreceipt)(id, self.projection, self.serial, kind))
        };
        let observed = self.observe_status();
        let returned = self.close_span();
        prepared.and(receipt).and(observed).and(returned)
    }

    fn observe_holder(&mut self) -> Result<(), LiveVcpuTimeCallbackError> {
        let api = self.api.ok_or_else(|| status_error(-libc::ESTALE))?;
        let kind = self.kind.ok_or_else(|| status_error(-libc::ESTALE))?;
        if !self.projection.is_null() {
            return Err(status_error(-libc::EBUSY));
        }
        let status = (api.holder_observe)(
            self.id,
            self.holder.get(),
            kind,
            &mut self.projection,
            &mut self.observed_serial,
        );
        // Local outputs are separate from the foreign canonical field.
        if !self.projection.is_null() && self.observed_serial != self.serial {
            self.uncertain = true;
        }
        native_status(status)?;
        if self.projection.is_null()
            || self.observed_serial != self.serial
            || !self.creation.is_null()
        {
            self.uncertain = true;
            return Err(status_error(-libc::EPROTO));
        }
        Ok(())
    }

    fn observe_status(&mut self) -> Result<(), LiveVcpuTimeCallbackError> {
        let owner = if !self.projection.is_null() {
            self.projection
        } else {
            self.creation
        };
        if owner.is_null() || self.serial == 0 {
            return Ok(());
        }
        let api = self.api.ok_or_else(|| status_error(-libc::ESTALE))?;
        let kind = self.kind.ok_or_else(|| status_error(-libc::ESTALE))?;
        let mut journal = Status::default();
        let status = (api.status_observe)(self.id, owner, self.serial, kind, &mut journal);
        if status == 0 {
            self.journal = Some(journal);
        }
        native_status(status)
    }

    fn close_span(&mut self) -> Result<(), LiveVcpuTimeCallbackError> {
        if !self.attempted || self.returned || self.span_closed || !self.creation.is_null() {
            return Ok(());
        }
        if !self.transfer_attempted
            || self.uncertain
            || self.projection.is_null()
            || self.serial == 0
        {
            return Err(status_error(-libc::ESTALE));
        }
        let api = self.api.ok_or_else(|| status_error(-libc::ESTALE))?;
        let kind = self.kind.ok_or_else(|| status_error(-libc::ESTALE))?;
        let original = self.projection;
        let status = (api.span_return)(self.id, &mut self.projection, self.serial, kind);
        if status != 0 {
            if self.projection != original {
                self.projection = original;
                self.uncertain = true;
            }
            return Err(status_error(status));
        }
        if !self.projection.is_null() {
            self.uncertain = true;
            return Err(status_error(-libc::EPROTO));
        }
        self.span = Span::empty();
        self.span_closed = true;
        Ok(())
    }

    fn identity_return(&mut self) -> Result<(), LiveVcpuTimeCallbackError> {
        if !self.attempted || self.returned {
            return Ok(());
        }
        if self.uncertain || self.serial == 0 {
            return Err(status_error(-libc::ESTALE));
        }
        let api = self.api.ok_or_else(|| status_error(-libc::ESTALE))?;
        let kind = self.kind.ok_or_else(|| status_error(-libc::ESTALE))?;
        let canonical = self.transfer_attempted && self.creation.is_null();
        if canonical && !self.span_closed {
            return Err(status_error(-libc::EBUSY));
        }
        let field = if canonical {
            self.holder.get()
        } else if !self.creation.is_null() {
            &mut self.creation
        } else {
            return Err(status_error(-libc::ESTALE));
        };
        native_status((api.owner_return)(self.id, field, self.serial, kind))?;
        if !canonical && !self.creation.is_null() {
            self.uncertain = true;
            return Err(status_error(-libc::EPROTO));
        }
        // True canonical return consumes the exact protected field on0; no
        // Rust field read or observation flag substitutes for that contract.
        self.returned = true;
        self.projection = std::ptr::null_mut();
        self.span = Span::empty();
        Ok(())
    }
}

fn source_error(source: StartupSourceError) -> LiveVcpuTimeCallbackError {
    LiveVcpuTimeCallbackError::CallbackRegistrationGroup { source }
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
