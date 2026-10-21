//! Retains the actual Native received-delivery lifetime in paid Runtime storage.
//!
//! Canonical holder fields belong to the pinned Runtime. Opaque projections and
//! serials only identify those fields. The separate first-bound payload callbacks
//! transfer actual local module custody; neither route grants an entered action,
//! callback activation or Host publisher return.
// SPDX-License-Identifier: GPL-2.0-only

use super::abi::Receive;
use super::{StartupSourceError, native_status, status_error};
use std::cell::UnsafeCell;

mod abi;
pub(super) use abi::Api;
use abi::Owner;

/// Keeps every born delivery, including a constructor's negative output.
pub(super) struct Delivery {
    creation: *mut Owner,
    projection: *mut Owner,
    holder: UnsafeCell<*mut Owner>,
    serial: u64,
    attempted: bool,
    transfer_attempted: bool,
    payload_attempted: bool,
    returned: bool,
    first_status: i32,
    payload_return_status: i32,
    ready_return_status: i32,
    ready_returned: bool,
}

impl Delivery {
    pub(super) const fn new() -> Self {
        Self {
            creation: std::ptr::null_mut(),
            projection: std::ptr::null_mut(),
            holder: UnsafeCell::new(std::ptr::null_mut()),
            serial: 0,
            attempted: false,
            transfer_attempted: false,
            payload_attempted: false,
            returned: false,
            first_status: 0,
            payload_return_status: 0,
            ready_return_status: 0,
            ready_returned: false,
        }
    }

    /// Receives lifetime custody through the actual retained Native receive.
    ///
    /// The containing Runtime is already pinned and paid, and Source validates
    /// its genuine receive/serial graph. Copied reader progress cannot create
    /// this owner. Every born output is saved before interpreting signed status.
    ///
    /// # Errors
    /// Retains constructor or transfer refusal, malformed born output, or a
    /// current-check failure. A negative result never permits another birth.
    pub(super) fn retain(
        &mut self,
        api: Api,
        id: u64,
        receive: *mut Receive,
        receive_serial: u64,
    ) -> Result<(), StartupSourceError> {
        if self.attempted {
            native_status(self.first_status)?;
            return self.current(api, id);
        }
        self.attempted = true;
        let first = (api.create)(
            id,
            receive,
            receive_serial,
            &mut self.creation,
            &mut self.serial,
        );
        self.projection = self.creation;
        self.record(first);

        // A negative constructor can still own a real delivery. Transfer its
        // identity before returning either failure, just as for the parent.
        let transfer = if !self.projection.is_null() && self.serial != 0 {
            self.transfer_attempted = true;
            let status = (api.transfer)(id, &mut self.creation, self.serial, self.holder.get());
            self.record(status);
            native_status(status)
        } else {
            Err(status_error(-libc::EPROTO))
        };

        // Claim only through the genuine first-bound child. Source journals
        // callback entry, actual born output and independent post separately;
        // even a failed receive can still contain its real module payload.
        let payload = if !self.projection.is_null() && self.serial != 0 {
            self.payload_attempted = true;
            let status = (api.payload_claim)(id, self.projection, self.serial);
            self.record(status);
            native_status(status)
        } else {
            Err(status_error(-libc::EPROTO))
        };

        native_status(first)?;
        transfer?;
        payload?;
        self.current(api, id)
    }

    fn record(&mut self, status: i32) {
        if self.first_status == 0 && status != 0 {
            self.first_status = status;
        }
    }

    fn current(&self, api: Api, id: u64) -> Result<(), StartupSourceError> {
        if self.returned {
            return Err(status_error(-libc::ESTALE));
        }
        if self.projection.is_null()
            || self.serial == 0
            || !self.transfer_attempted
            || !self.creation.is_null()
        {
            return Err(status_error(-libc::EPROTO));
        }
        native_status((api.current)(id, self.projection, self.serial))
    }

    /// Returns only this delivery's exact canonical lifetime holder.
    ///
    /// The final pure Source entry consumes its field only on zero. Every negative
    /// retains the holder and dependencies, including live native borrowers.
    /// Ready handoff return records its physical consumption independently.
    /// A separate first-bound callback then attempts actual module payload
    /// retirement. Pure lifetime return then independently checks Native's
    /// retained debt; a negative payload post cannot resurrect a consumed owner.
    /// This proves no Host publisher, peer or physical resource return.
    ///
    /// # Errors
    /// Retains malformed or refused custody. A projection or current result
    /// cannot substitute for consumption of the exact canonical holder.
    pub(super) fn identity_return(&mut self, api: Api, id: u64) -> Result<(), StartupSourceError> {
        if !self.attempted || self.returned {
            return Ok(());
        }
        if self.projection.is_null() || self.serial == 0 {
            return Err(status_error(-libc::EPROTO));
        }
        let mut ready_returned = 0;
        let status = (api.ready_return)(id, self.projection, self.serial, &mut ready_returned);
        // The factual output records consumption before independent Native post.
        // It never grants permission: both later returns authenticate real debt.
        self.ready_returned |= ready_returned == 1;
        if self.ready_return_status == 0 {
            self.ready_return_status = if status != 0 {
                status
            } else if ready_returned != 1 {
                -libc::EPROTO
            } else {
                0
            };
        }
        let ready = native_status(self.ready_return_status);
        let payload = if self.payload_attempted {
            let status = (api.payload_return)(id, self.projection, self.serial);
            if self.payload_return_status == 0 && status != 0 {
                self.payload_return_status = status;
            }
            native_status(self.payload_return_status)
        } else {
            Ok(())
        };
        let canonical = self.transfer_attempted && self.creation.is_null();
        let field = if canonical {
            self.holder.get()
        } else {
            &mut self.creation
        };
        let lifetime = native_status((api.identity_return)(id, field, self.serial));
        if let Err(error) = lifetime {
            // Native alone decides whether the actual module payload and local
            // borrowers are closed. Preserve the initiating payload refusal.
            ready?;
            payload?;
            return Err(error);
        }
        // SAFETY: `field` selects this exclusively borrowed keeper's actual
        // creation or canonical cell. The synchronous pure return entry cannot
        // retain an access after returning; the cell remains live and aligned.
        // A zero status alone cannot replace consumption of that exact field.
        if unsafe { !field.read().is_null() } {
            return Err(status_error(-libc::EPROTO));
        }

        self.projection = std::ptr::null_mut();
        self.serial = 0;
        // A returned local delivery cannot reissue from the same still-retained
        // receive. Only actual parent receive consumption permits a new keeper.
        self.returned = true;
        // Save real lifetime consumption before reporting an independent
        // Ready or payload return post failure. A later cleanup cannot reissue it.
        ready?;
        payload
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(super) fn model_api() -> Api {
    tests::fresh_api()
}

#[cfg(test)]
pub(super) fn model_calls() -> (usize, usize, usize) {
    tests::calls()
}
