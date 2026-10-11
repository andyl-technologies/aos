//! Original teardown mailbox ownership for local native worker enrollment.
//!
//! The retained allocation owns the actual receiver passed to the installed
//! worker. A received trigger remains owned before modeled admission, so holding
//! that admission cannot discard or dispatch the trigger. This mailbox does not
//! inspect unseen channel messages or fence their producers, and is not a
//! capture image or closed-input certificate.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(test)]
use std::sync::mpsc;

use super::teardown_channel::TeardownReceiver;
use std::sync::atomic::AtomicU64;

use thiserror::Error;

use super::LiveRuntimeTeardownTrigger;

/// Retains the actual receiver and the first received original trigger.
pub(super) struct InstalledTeardownMailbox {
    process_id: u32,
    receiver: Mutex<TeardownReceiver>,
    bounded_sequence: AtomicU64,
    original: Mutex<Option<LiveRuntimeTeardownTrigger>>,
    reader_started: AtomicBool,
    failed: AtomicBool,
}

/// Refuses invalid lifetime or mailbox ownership without authorizing teardown.
#[derive(Debug, Error)]
pub(super) enum InstalledTeardownMailboxError {
    #[error("original teardown receiver belongs to another process or worker")]
    Lifetime,
    #[error("original teardown mailbox ownership is poisoned")]
    Ownership,
    #[error("original teardown signalers disconnected")]
    Disconnected,
    #[error("original teardown trigger has not been retained")]
    MissingTrigger,
}

impl InstalledTeardownMailbox {
    /// Retains the actual installation receiver without replacing its channel.
    pub(super) fn new(receiver: impl Into<TeardownReceiver>) -> Arc<Self> {
        Arc::new(Self {
            process_id: std::process::id(),
            receiver: Mutex::new(receiver.into()),
            bounded_sequence: AtomicU64::new(0),
            original: Mutex::new(None),
            reader_started: AtomicBool::new(false),
            failed: AtomicBool::new(false),
        })
    }

    /// Receives and retains one trigger before the worker requests modeled entry.
    ///
    /// The caller marks its actual modeled worker idle before this receive and
    /// enrolls that same worker with the source registrar. This method never
    /// enters or releases modeled admission.
    ///
    /// # Errors
    /// Refuses another process, duplicate reader, poison or disconnected signalers.
    /// The original receiver and any retained trigger remain owned on failure.
    pub(super) fn receive_original(&self) -> Result<(), InstalledTeardownMailboxError> {
        if std::process::id() != self.process_id {
            // Refuse before an inherited parent mutex can be touched.
            return Err(InstalledTeardownMailboxError::Lifetime);
        }
        if self
            .reader_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.failed.store(true, Ordering::Release);
            return Err(InstalledTeardownMailboxError::Lifetime);
        }

        let received = self
            .receiver
            .lock()
            .map_err(|_| {
                self.failed.store(true, Ordering::Release);
                InstalledTeardownMailboxError::Ownership
            })?
            .receive_retained()
            .map_err(|_| InstalledTeardownMailboxError::Disconnected);
        let trigger = match received {
            Ok(trigger) => trigger,
            Err(error) => {
                self.failed.store(true, Ordering::Release);
                return Err(error);
            }
        };

        let mut original = self.original.lock().map_err(|_| {
            self.failed.store(true, Ordering::Release);
            InstalledTeardownMailboxError::Ownership
        })?;
        if original.is_some() {
            self.failed.store(true, Ordering::Release);
            return Err(InstalledTeardownMailboxError::Lifetime);
        }
        match trigger {
            super::teardown_channel::RetainedTrigger::Legacy(trigger) => *original = Some(trigger),
            super::teardown_channel::RetainedTrigger::Bounded(sequence) => {
                self.bounded_sequence.store(sequence, Ordering::Release);
            }
        }
        Ok(())
    }

    /// Consumes the retained trigger only after the actual worker enters its gate.
    ///
    /// The runtime calls this after its existing modeled-worker entry returns.
    /// Local registration and local hold observations supply no such entry.
    ///
    /// # Errors
    /// Refuses another process, sticky failure, poisoned ownership or an absent
    /// trigger. None of these failures substitutes a shutdown request.
    pub(super) fn take_after_modeled_entry(
        &self,
    ) -> Result<LiveRuntimeTeardownTrigger, InstalledTeardownMailboxError> {
        if std::process::id() != self.process_id || self.failed.load(Ordering::Acquire) {
            return Err(InstalledTeardownMailboxError::Lifetime);
        }
        let sequence = self.bounded_sequence.load(Ordering::Acquire);
        if sequence != 0 {
            return self
                .receiver
                .try_lock()
                .map_err(|_| InstalledTeardownMailboxError::Ownership)?
                .take_bounded(sequence)
                .map_err(|_| InstalledTeardownMailboxError::Ownership);
        }
        self.original
            .lock()
            .map_err(|_| {
                self.failed.store(true, Ordering::Release);
                InstalledTeardownMailboxError::Ownership
            })?
            .take()
            .ok_or(InstalledTeardownMailboxError::MissingTrigger)
    }

    /// Checks original lifetime and poison without waiting on the blocking receiver.
    ///
    /// This does not assert an empty channel or replace actual worker admission.
    pub(super) fn lifetime_valid(&self) -> bool {
        std::process::id() == self.process_id
            && !self.failed.load(Ordering::Acquire)
            && !self.receiver.is_poisoned()
            && !self.original.is_poisoned()
    }
}

/// Receives on the same actual worker, retaining its trigger before modeled entry.
///
/// Enrollment retries preserve the receiver and never release a modeled hold.
#[cfg(not(test))]
pub(super) fn run_installed_teardown_worker(
    mailbox: Arc<InstalledTeardownMailbox>,
    endpoint: Arc<super::installed_endpoint_owner::InstalledEndpointCustody>,
    handle: super::LiveControlTeardownHandle,
    request_shutdown: super::QemuRequestShutdownFn,
    workers: Arc<super::LiveWorkerQuiescence>,
) {
    let idle = workers.idle(super::WORKER_TEARDOWN);
    loop {
        match endpoint.enroll_teardown() {
            Ok(true) => break,
            Ok(false) => std::thread::yield_now(),
            Err(status) => {
                super::emit_control_worker_diagnostic(&format!(
                    "original teardown enrollment refused: {status}"
                ));
                std::process::abort();
            }
        }
    }
    if let Err(error) = mailbox.receive_original() {
        super::emit_control_worker_diagnostic(&error.to_string());
        std::process::abort();
    }
    let pending = idle.received();
    let _operation = pending.enter();
    let trigger = match mailbox.take_after_modeled_entry() {
        Ok(trigger) => trigger,
        Err(error) => {
            super::emit_control_worker_diagnostic(&error.to_string());
            std::process::abort();
        }
    };
    super::complete_live_teardown(trigger, handle, request_shutdown);
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Failed ownership and gate assertions deliberately panic in these real-channel tests.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "installed_teardown_tests.rs"]
mod tests;
