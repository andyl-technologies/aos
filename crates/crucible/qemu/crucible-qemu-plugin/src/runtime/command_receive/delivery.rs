//! Retains the actual Native received-delivery lifetime in paid Runtime storage.
//!
//! Canonical holder fields belong to the pinned Runtime. Opaque projections and
//! serials only identify those fields; they grant no action, module payload
//! retirement, callback activation or Host publisher return.
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
    returned: bool,
    first_status: i32,
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
            returned: false,
            first_status: 0,
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

        native_status(first)?;
        transfer?;
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
    /// This pure Source entry consumes its field only on zero. Every negative
    /// retains the holder and dependencies, including live native borrowers.
    /// It performs no module callback, free or operation postcheck and proves
    /// no peer, payload or physical resource return.
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
        let canonical = self.transfer_attempted && self.creation.is_null();
        let field = if canonical {
            self.holder.get()
        } else {
            &mut self.creation
        };
        native_status((api.identity_return)(id, field, self.serial))?;
        if !canonical && !self.creation.is_null() {
            return Err(status_error(-libc::EPROTO));
        }

        self.projection = std::ptr::null_mut();
        self.serial = 0;
        // A returned local delivery cannot reissue from the same still-retained
        // receive. Only actual parent receive consumption permits a new keeper.
        self.returned = true;
        Ok(())
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
