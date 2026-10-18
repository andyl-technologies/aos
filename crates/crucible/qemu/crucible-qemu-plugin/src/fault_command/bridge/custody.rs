//! Journals destructive native effects and retains uncertain local receipts.
//!
//! Serials distinguish local attempts only. They issue no operation, clock or
//! semantic permission. A negative return cannot prove that native work did not
//! occur; the same bridge keeps its command/correlation or raw output until an
//! authentic disposition exists. No such recovery producer is supplied here.

// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[derive(Default)]
pub(in crate::fault_command) struct EffectCustody {
    next_serial: u64,
    pub(in crate::fault_command) submit: Option<SubmissionReceipt>,
    pub(in crate::fault_command) dispatch: Option<DispatchReceipt>,
    pub(in crate::fault_command) result: Option<PollReceipt<QemuFaultResult>>,
    pub(in crate::fault_command) event: Option<PollReceipt<QemuFaultEvent>>,
    blocked: Option<&'static str>,
}

pub(in crate::fault_command) struct Attempt {
    pub(in crate::fault_command) serial: u64,
    pub(in crate::fault_command) returned_status: Option<i32>,
}

pub(in crate::fault_command) struct SubmissionReceipt {
    pub(in crate::fault_command) attempt: Attempt,
    pub(in crate::fault_command) command: QemuFaultCommand,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::fault_command) struct DispatchKey {
    pub(in crate::fault_command) control_request: u64,
    pub(in crate::fault_command) frontier: u64,
    pub(in crate::fault_command) raw_icount: u64,
}

pub(in crate::fault_command) struct DispatchReceipt {
    pub(in crate::fault_command) key: DispatchKey,
    pub(in crate::fault_command) attempt: Attempt,
}

pub(in crate::fault_command) struct PollReceipt<T> {
    pub(in crate::fault_command) attempt: Attempt,
    pub(in crate::fault_command) peeked: T,
    pub(in crate::fault_command) raw: T,
    pub(in crate::fault_command) payload: Vec<u8>,
    pub(in crate::fault_command) payload_len: usize,
    pub(in crate::fault_command) publication_attempted: bool,
    pub(in crate::fault_command) published: bool,
}

impl EffectCustody {
    pub(in crate::fault_command) fn check(&self) -> Result<(), FaultCommandBridgeError> {
        if let Some(stage) = self.blocked {
            let (attempt, publication_attempted, published) = match stage {
                "native submit" => (
                    self.submit.as_ref().map(|receipt| &receipt.attempt),
                    false,
                    false,
                ),
                "node-boundary dispatch" => (
                    self.dispatch.as_ref().map(|receipt| &receipt.attempt),
                    false,
                    false,
                ),
                "result publication" => (
                    self.result.as_ref().map(|receipt| &receipt.attempt),
                    self.result
                        .as_ref()
                        .is_some_and(|receipt| receipt.publication_attempted),
                    self.result
                        .as_ref()
                        .is_some_and(|receipt| receipt.published),
                ),
                "event publication" => (
                    self.event.as_ref().map(|receipt| &receipt.attempt),
                    self.event
                        .as_ref()
                        .is_some_and(|receipt| receipt.publication_attempted),
                    self.event.as_ref().is_some_and(|receipt| receipt.published),
                ),
                _ => (None, false, false),
            };
            return Err(FaultCommandBridgeError::EffectUnresolved {
                stage,
                serial: attempt.map(|attempt| attempt.serial),
                native_status: attempt.and_then(|attempt| attempt.returned_status),
                publication_attempted,
                published,
            });
        }
        Ok(())
    }

    pub(in crate::fault_command) fn begin(&mut self) -> Result<Attempt, FaultCommandBridgeError> {
        self.check()?;
        self.next_serial = self
            .next_serial
            .checked_add(1)
            .ok_or(FaultCommandBridgeError::ReceiptSerialOverflow)?;
        Ok(Attempt {
            serial: self.next_serial,
            returned_status: None,
        })
    }

    pub(in crate::fault_command) fn block(&mut self, stage: &'static str) {
        self.blocked.get_or_insert(stage);
    }
}

/// Reports missing local journal storage without projecting a native effect.
pub(super) fn missing_receipt(stage: &'static str) -> FaultCommandBridgeError {
    FaultCommandBridgeError::EffectUnresolved {
        stage,
        serial: None,
        native_status: None,
        publication_attempted: false,
        published: false,
    }
}
