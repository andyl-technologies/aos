//! Keeps physical command membership and received request debt in paid Runtime.
//!
//! All Native canonical fields are raw-address UnsafeCell storage. Separate
//! module projections never authorize polling, dequeue, mutation or replay.
//! The containing mutex serializes module calls; Source's own registry owns its
//! fields and retains the child while the distinct bounded reader runs.
// SPDX-License-Identifier: GPL-2.0-only

use super::control_component::NativeComponent;
use super::live_callbacks::{ControlIntentFacts, ReceiveProgress};
use crate::StartupSourceError;
use std::cell::UnsafeCell;

mod abi;
mod delivery;
use abi::{Api, Member, Reader, Receive, Status, Writer};
pub(super) use abi::PayloadCallbacks;

/// Retains the same physical member/receive graph inside the paid pinned Runtime.
pub(super) struct CommandReceive {
    api: Option<Api>,
    id: u64,
    process: u32,
    member_creation: *mut Member,
    member: *mut Member,
    member_holder: UnsafeCell<*mut Member>,
    member_attempted: bool,
    member_transfer_attempted: bool,
    receive_creation: *mut Receive,
    receive: *mut Receive,
    receive_holder: UnsafeCell<*mut Receive>,
    serial: u64,
    receive_attempted: bool,
    receive_transfer_attempted: bool,
    delivery: delivery::Delivery,
    facts: Option<ControlIntentFacts>,
    progress: ReceiveProgress,
    journal: Status,
    first_status: i32,
}

impl CommandReceive {
    pub(super) const fn new() -> Self {
        Self {
            api: None,
            id: 0,
            process: 0,
            member_creation: std::ptr::null_mut(),
            member: std::ptr::null_mut(),
            member_holder: UnsafeCell::new(std::ptr::null_mut()),
            member_attempted: false,
            member_transfer_attempted: false,
            receive_creation: std::ptr::null_mut(),
            receive: std::ptr::null_mut(),
            receive_holder: UnsafeCell::new(std::ptr::null_mut()),
            serial: 0,
            receive_attempted: false,
            receive_transfer_attempted: false,
            delivery: delivery::Delivery::new(),
            facts: None,
            progress: ReceiveProgress {
                first_status: 0,
                post_status: 0,
                read_attempted: 0,
                request_received: 0,
                reader_released: 0,
            },
            journal: Status {
                serial: 0,
                publisher_sequence: 0,
                first_status: 0,
                reader_status: 0,
                validation_status: 0,
                post_status: 0,
                invocation_attempted: 0,
                invocation_returned: 0,
                progress_valid: 0,
                terminal_uncertain: 0,
            },
            first_status: 0,
        }
    }

    /// Enrolls the reader, Park writer and payload endpoints at first member birth.
    ///
    /// # Safety
    /// This keeper is already inline in paid pinned Runtime. Component is a
    /// protected genuine Source projection, never a caller-manufactured tuple.
    ///
    /// # Errors
    /// Preserves every early owner and real transfer before independent refusal.
    pub(super) unsafe fn enroll(
        &mut self,
        id: u64,
        component: *mut NativeComponent,
        reader: Reader,
        writer: Writer,
        payload: PayloadCallbacks,
    ) -> Result<(), StartupSourceError> {
        if self.member_attempted {
            return Err(status_error(-libc::EALREADY));
        }
        let api = Api::resolve()?;
        self.enroll_using(id, component, reader, writer, payload, api)
    }

    fn enroll_using(
        &mut self,
        id: u64,
        component: *mut NativeComponent,
        reader: Reader,
        writer: Writer,
        payload: PayloadCallbacks,
        api: Api,
    ) -> Result<(), StartupSourceError> {
        if self.member_attempted {
            return Err(status_error(-libc::EALREADY));
        }
        self.api = Some(api);
        self.id = id;
        self.process = std::process::id();
        self.member_attempted = true;
        let first = (api.member_create)(
            id,
            component,
            reader,
            writer,
            payload.claim,
            payload.release,
            payload.borrow_acquire,
            payload.borrow_release,
            &mut self.member_creation,
        );
        self.member = self.member_creation;
        self.record(first);
        native_status(first)?;
        if self.member.is_null() {
            return Err(status_error(-libc::EPROTO));
        }
        self.member_transfer_attempted = true;
        let first = (api.member_transfer)(id, &mut self.member_creation, self.member_holder.get());
        self.record(first);
        native_status(first)?;
        if !self.member_creation.is_null() {
            return Err(status_error(-libc::EPROTO));
        }
        let current = (api.member_current)(id, self.member);
        self.record(current);
        native_status(current)
    }

    fn record(&mut self, status: i32) {
        if self.first_status == 0 && status != 0 {
            self.first_status = status;
        }
    }

    /// Captures only physical receipt through the genuine outside-BQL ready cut.
    ///
    /// # Errors
    /// Refuses context, current or partial custody without replay. Received and
    /// unknown release debt remains retained and never admits command effects.
    pub(super) fn receive_at_ready(&mut self) -> Result<(), StartupSourceError> {
        if self.process != std::process::id()
            || self.member.is_null()
            || !self.member_transfer_attempted
            || !self.member_creation.is_null()
        {
            return Err(status_error(-libc::ESTALE));
        }
        let api = self.api.ok_or_else(|| status_error(-libc::ESTALE))?;
        if self.receive_attempted {
            if self.first_status != 0 {
                return Err(status_error(self.first_status));
            }
            if self.receive.is_null() || self.serial == 0 {
                return Err(status_error(if self.first_status == 0 {
                    -libc::EPROTO
                } else {
                    self.first_status
                }));
            }
            native_status((api.receive_current)(self.id, self.receive, self.serial))?;
            return self.retain_delivery(api);
        }
        native_status((api.member_current)(self.id, self.member))?;
        // A prior no-request loan can be replaced only after actual Source
        // identity return consumed its exact field. No local phase grants this.
        self.first_status = 0;
        self.receive_attempted = true;
        let first = (api.receive_create)(
            self.id,
            self.member,
            &mut self.receive_creation,
            &mut self.serial,
        );
        self.receive = self.receive_creation;
        self.record(first);
        // Observe every born receipt before interpreting the signed constructor.
        let observation = if !self.receive.is_null() && self.serial != 0 {
            self.observe(api)
        } else {
            Err(status_error(-libc::ESTALE))
        };
        if let Err(StartupSourceError::NativeStatus { status }) = &observation {
            self.record(*status);
        }
        // Born negative/uncertain custody can move by identity; this creates no
        // continuation permission and Source refuses active invocation/creation.
        let transfer = if !self.receive.is_null() && self.serial != 0 {
            self.receive_transfer_attempted = true;
            let status = (api.receive_transfer)(
                self.id,
                &mut self.receive_creation,
                self.serial,
                self.receive_holder.get(),
            );
            self.record(status);
            native_status(status)
        } else {
            Err(status_error(-libc::ESTALE))
        };
        // Preserve actual delivery custody before interpreting any independent
        // receive failure. Source checks the real receipt graph; these copied
        // progress fields can only gate an attempt, never issue its owner.
        let delivery = self.retain_delivery(api);
        if let Err(StartupSourceError::NativeStatus { status }) = &delivery {
            self.record(*status);
        }
        native_status(first)?;
        observation?;
        transfer?;
        delivery?;
        if !self.receive_creation.is_null() {
            return Err(status_error(-libc::EPROTO));
        }
        native_status((api.receive_current)(self.id, self.receive, self.serial))
    }

    fn retain_delivery(&mut self, api: Api) -> Result<(), StartupSourceError> {
        if self.progress.request_received != 1 {
            return Ok(());
        }
        if self.receive.is_null() || self.serial == 0 {
            return Err(status_error(-libc::EPROTO));
        }
        self.delivery
            .retain(api.delivery, self.id, self.receive, self.serial)
    }

    /// Reports retained copied facts even when the actual receiving post refused.
    pub(super) fn ready_facts(&mut self) -> super::live_callbacks::ReadyObservation {
        let result = self.receive_at_ready();
        let status = match result {
            Ok(()) => 0,
            Err(StartupSourceError::NativeStatus { status }) => status,
            Err(_) => -libc::ESTALE,
        };
        let facts = self.facts;
        if self.known_no_request() {
            // This predicate only permits an identity-return attempt. Source
            // independently checks all child/phase/debt and consumes the field.
            // A refusal preserves both custody and the initiating read cause.
            let _returned = self.return_receive();
        }
        super::live_callbacks::ReadyObservation { facts, status }
    }

    fn known_no_request(&self) -> bool {
        self.receive_attempted
            && self.progress.read_attempted == 1
            && self.progress.request_received == 0
            && self.progress.reader_released == 1
            && self.progress.first_status == -libc::ENOENT
            && self.progress.post_status == 0
            && self.journal.first_status == 0
            && self.journal.reader_status == -libc::ENOENT
            && self.journal.validation_status == 0
            && self.journal.post_status == 0
            && self.journal.invocation_attempted == 1
            && self.journal.invocation_returned == 1
            && self.journal.progress_valid == 1
            && self.journal.terminal_uncertain == 0
    }

    fn return_receive(&mut self) -> Result<(), StartupSourceError> {
        let api = self.api.ok_or_else(|| status_error(-libc::ESTALE))?;
        if self.receive.is_null() || self.serial == 0 {
            return Err(status_error(-libc::ESTALE));
        }
        if let Err(error) = self.delivery.identity_return(api.delivery, self.id) {
            if let StartupSourceError::NativeStatus { status } = &error {
                self.record(*status);
            }
            return Err(error);
        }
        let canonical = self.receive_transfer_attempted && self.receive_creation.is_null();
        let field = if canonical {
            self.receive_holder.get()
        } else {
            &mut self.receive_creation
        };
        native_status((api.receive_return)(self.id, field, self.serial))?;
        if !canonical && !self.receive_creation.is_null() {
            return Err(status_error(-libc::EPROTO));
        }
        // The matched pure return consumes this exact canonical field on0;
        // there is no post/getter and Rust never reads the foreign field.
        self.receive = std::ptr::null_mut();
        self.serial = 0;
        self.receive_attempted = false;
        self.receive_transfer_attempted = false;
        self.delivery = delivery::Delivery::new();
        Ok(())
    }

    fn observe(&mut self, api: Api) -> Result<(), StartupSourceError> {
        let mut facts = ControlIntentFacts {
            control_sequence: 0,
            command_producer_ordinal: 0,
            sample_generation: 0,
            installed_sample_generation: 0,
            sampler_configured: 0,
            sample_present: 0,
        };
        let mut progress = ReceiveProgress::default();
        let mut journal = Status::default();
        let status = (api.receive_observe)(
            self.id,
            self.receive,
            self.serial,
            &mut facts,
            &mut progress,
            &mut journal,
        );
        native_status(status)?;
        self.progress = progress;
        self.journal = journal;
        self.facts = (progress.request_received == 1).then_some(facts);
        // Source publishes the complete journal with observer status0. Preserve
        // it before refusing incoherent phases; zero coordinates remain valid.
        if journal.serial != self.serial
            || progress.read_attempted > 1
            || progress.request_received > 1
            || progress.reader_released > 1
            || journal.invocation_attempted > 1
            || journal.invocation_returned > 1
            || journal.progress_valid > 1
            || journal.terminal_uncertain > 1
            || (progress.request_received == 1 && progress.read_attempted != 1)
            || (progress.reader_released == 1 && progress.read_attempted != 1)
        {
            return Err(status_error(-libc::EPROTO));
        }
        Ok(())
    }

    /// Returns only actual identity custody; received requests need a peer producer.
    ///
    /// # Errors
    /// Retains unknown local release or received-request/material debt, then
    /// refuses member return. ACK, current or a local released flag cannot clear it.
    pub(super) fn identity_return(&mut self) -> Result<(), StartupSourceError> {
        if !self.member_attempted {
            return Ok(());
        }
        if self.process != std::process::id() {
            return Err(status_error(-libc::ESTALE));
        }
        let api = self.api.ok_or_else(|| status_error(-libc::ESTALE))?;
        if self.receive_attempted {
            self.return_receive()?;
        }
        if self.member.is_null() {
            return Err(status_error(-libc::ESTALE));
        }
        let canonical = self.member_transfer_attempted && self.member_creation.is_null();
        let field = if canonical {
            self.member_holder.get()
        } else {
            &mut self.member_creation
        };
        native_status((api.member_return)(self.id, field))?;
        if !canonical && !self.member_creation.is_null() {
            return Err(status_error(-libc::EPROTO));
        }
        self.member = std::ptr::null_mut();
        self.member_attempted = false;
        Ok(())
    }
}

fn native_status(status: i32) -> Result<(), StartupSourceError> {
    if status == 0 {
        Ok(())
    } else {
        Err(status_error(status))
    }
}

fn status_error(status: i32) -> StartupSourceError {
    StartupSourceError::NativeStatus { status }
}

#[cfg(test)]
mod tests;
