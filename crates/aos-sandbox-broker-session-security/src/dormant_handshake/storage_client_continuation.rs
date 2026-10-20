//! Drives the sole same-owner Storage Client transition under a closed purpose.
//!
//! Runtime transfers its actual idle Session before fallible retirement. The
//! genuine J/Cache or C23/B borrower stays live through terminal qualification,
//! transport disposal and the same three signed HELLO records. Every later
//! request still needs its independently admitted plan and original authority.

use super::*;
use aos_sandbox::{OriginalCreateStorageClientSessionV1, OriginalCreateStorageReadyV1};
use crate::handshake::client_storage_continuation::{ClientTransitionClosedV1, RetainedStorageClientTransitionV1};

/// Reports a closed actual Client transition with all partial owners retained.
#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
#[error("original Storage Client transition is closed; actual custody remains resident")]
pub struct OriginalStorageClientTransitionClosedV1;

#[derive(Default)]
struct ReadinessOriginalV1 {
    native: Option<Result<usize, rustix::io::Errno>>,
    returned: Option<Result<(), DormantBrokerSessionHandshakeErrorV1>>,
}

impl ReadinessOriginalV1 {
    fn observe_once(&mut self, descriptor: BorrowedFd<'_>, write: bool, deadline: u64) -> bool {
        if self.returned.is_some() { return false; }
        self.returned = Some(wait_for_handshake_readiness_retaining_v1(descriptor, write, deadline, &mut self.native));
        matches!(self.returned, Some(Ok(())))
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native.as_ref().and_then(|result| result.as_ref().err())
            .filter(|cause| **cause != rustix::io::Errno::INTR)
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.returned.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }
}

/// Keeps the old idle Session and every failed transition prefix resident.
#[doc(hidden)]
#[must_use = "retain failed Client custody or take its actual completed Session once"]
pub struct OriginalStorageClientSessionTransitionV1 {
    old: Option<DormantAuthenticatedBrokerSessionV1>,
    inner: Option<RetainedStorageClientTransitionV1>,
    readiness: Option<ReadinessOriginalV1>,
    host_tickets: Option<Vec<aos_sandbox_host::DormantHostScopeReplayTicketV1>>,
    closed: Option<OriginalStorageClientTransitionClosedV1>,
    started: bool,
    provisioning_handoff_entered: bool,
    provisioning_borrowed: Option<Result<(), aos_sandbox::CreateStorageClientSessionClosedV1>>,
    provisioning_predecessor: Option<Result<(), aos_sandbox::CreateProvisioningClientSessionAssociationErrorV1>>,
    provisioning_lineage: Option<Result<(), BrokerSessionSecurityError>>,
}

impl OriginalStorageClientSessionTransitionV1 {
    /// Moves the actual idle Session into an inert transition destination.
    #[doc(hidden)]
    #[must_use]
    pub fn retain(session: DormantAuthenticatedBrokerSessionV1) -> Self {
        Self { old: Some(session), inner: None, readiness: None, host_tickets: None, closed: None, started: false,
            provisioning_predecessor: None, provisioning_lineage: None,
            provisioning_handoff_entered: false, provisioning_borrowed: None }
    }

    fn close<T>(&mut self) -> Result<T, OriginalStorageClientTransitionClosedV1> {
        self.closed.get_or_insert(OriginalStorageClientTransitionClosedV1);
        Err(OriginalStorageClientTransitionClosedV1)
    }

    fn begin_provisioning_handoff_v1(&mut self)
        -> Result<&crate::handshake::client_storage_continuation::CompletedStorageClientRolloverV1,
            OriginalStorageClientTransitionClosedV1>
    {
        if self.provisioning_handoff_entered || self.closed.is_some() || self.readiness.is_some() {
            return self.close();
        }
        self.provisioning_handoff_entered = true;
        match self.inner.as_ref().and_then(|inner| inner.completed_rollover_v1()) {
            Some(rollover) => Ok(rollover),
            None => Err(OriginalStorageClientTransitionClosedV1),
        }
    }

    /// Runs the same kernel from the genuine completed-J predecessor under C23.
    ///
    /// The initial capture is continuously borrowed; this owner continuously
    /// owns the whole actual Session. The private native loan selects the fixed
    /// Apply/Inventory/GuestRoot profile and retains its original node and deadline.
    /// Neither this HELLO nor its profile authorizes an Apply request.
    ///
    /// # Errors
    /// Retains every lineage, fixed/payment, terminal/End/currentness and raw
    /// HELLO failure. The caller must finish the same independently owed C23
    /// native post even when construction or this finite turn refuses.
    #[doc(hidden)]
    pub fn run_provisioning_once_v1(
        &mut self,
        predecessor: &mut OriginalStorageClientSessionTransitionV1,
        capture: &DormantControllerInitialSessionOpenV1,
        receiving: &mut aos_sandbox::OriginalCreateProvisioningRootLoanV1<'_, '_>,
        controller: &aos_sandbox::Journal,
        complete: aos_sandbox_core::ResourceVector,
        actual_runtime_idle_bytes: usize,
    ) -> Result<(), OriginalStorageClientTransitionClosedV1> {
        if self.started || self.closed.is_some() || self.provisioning_lineage.is_some()
            || self.provisioning_borrowed.is_some()
        {
            return self.close();
        }
        let rollover = match predecessor.begin_provisioning_handoff_v1() {
            Ok(rollover) => rollover,
            Err(_) => return self.close(),
        };
        let old = match self.old.as_mut() { Some(old) if old.1.is_empty() => old, _ => return self.close() };
        let initial = match capture.original_after_completed_preparation_v1(rollover, &mut old.0) {
            Ok(initial) => {
                self.provisioning_lineage = Some(Ok(()));
                initial
            }
            Err(cause) => {
                self.provisioning_lineage = Some(Err(cause));
                return self.close();
            }
        };
        let mut original = match old.0.borrow_create_provisioning_client_once_v1(
            initial, receiving, controller, complete,
        ) {
            Ok(Ok(original)) => {
                self.provisioning_borrowed = Some(Ok(()));
                original
            }
            Ok(Err(cause)) => {
                self.provisioning_borrowed = Some(Err(cause));
                return self.close();
            }
            Err(cause) => {
                self.provisioning_lineage = Some(Err(cause));
                return self.close();
            }
        };
        // The concrete initial original remains borrowed by this loan while
        // run_once purely transfers the same whole Session to the same kernel.
        self.run_with_predecessor_v1(&mut original, actual_runtime_idle_bytes, Some(rollover))
    }

    /// Borrows the chronological actual Client cause through this same C23.
    #[doc(hidden)]
    #[must_use]
    pub fn failure_with_provisioning_v1<'cause>(
        &'cause self,
        receiving: &'cause aos_sandbox::CreateProvisioningOriginalsV1,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = &self.provisioning_lineage { return Some(cause); }
        let native = receiving.storage_apply_client_failure_v1();
        if let Some(Err(cause)) = &self.provisioning_borrowed { return native.or(Some(cause)); }
        self.failure_with_native_cause(native)
    }

    /// Runs the closed turn on the SAME genuine J and completed Cache original.
    ///
    /// The Runtime caller supplies only its actual idle-owner inline layout.
    /// All Security, raw, model and native geometry derives from actual private
    /// types. This method neither opens another Journal nor reloads credentials.
    ///
    /// # Errors
    /// Retains pending Host tickets, failed terminal/native/End/currentness,
    /// raw connect/HELLO, readiness or admission originals and refuses reuse.
    #[doc(hidden)]
    pub fn run_once(
        &mut self,
        original: &mut OriginalCreateStorageClientSessionV1<'_, '_, '_>,
        actual_runtime_idle_bytes: usize,
    ) -> Result<(), OriginalStorageClientTransitionClosedV1> {
        self.run_with_predecessor_v1(original, actual_runtime_idle_bytes, None)
    }

    fn run_with_predecessor_v1(
        &mut self,
        original: &mut OriginalCreateStorageClientSessionV1<'_, '_, '_>,
        actual_runtime_idle_bytes: usize,
        predecessor: Option<&crate::handshake::client_storage_continuation::CompletedStorageClientRolloverV1>,
    ) -> Result<(), OriginalStorageClientTransitionClosedV1> {
        if self.started || self.closed.is_some() { return self.close(); }
        self.started = true;
        let old = match self.old.as_ref() { Some(old) => old, None => return self.close() };
        if !old.1.is_empty() { return self.close(); }
        let actual_bytes = match actual_runtime_idle_bytes.checked_add(std::mem::size_of::<Self>()) {
            Some(bytes) => bytes,
            None => return self.close(),
        };
        let DormantAuthenticatedBrokerSessionV1(session, tickets) = match self.old.take() {
            Some(old) => old,
            None => return self.close(),
        };
        self.host_tickets = Some(tickets);
        self.inner = Some(match predecessor {
            Some(predecessor) => RetainedStorageClientTransitionV1::new_from_completed_predecessor_v1(session, predecessor),
            None => RetainedStorageClientTransitionV1::new(session),
        });
        let inner = match self.inner.as_mut() { Some(inner) => inner, None => std::process::abort() };
        if inner.retire_once(original, actual_bytes).is_err() { return self.close(); }
        if inner.begin_hello_once(original).is_err() {
            inner.observe_failed_hello_posts_once(original);
            return self.close();
        }
        loop {
            match inner.advance_hello_once(original) {
                Ok(true) => return Ok(()),
                Ok(false) => {
                    let (descriptor, write, deadline) = match inner.pending_readiness() {
                        Ok(pending) => pending,
                        Err(_) => {
                            inner.observe_failed_hello_posts_once(original);
                            return self.close();
                        }
                    };
                    self.readiness = Some(ReadinessOriginalV1::default());
                    let readiness = match self.readiness.as_mut() { Some(readiness) => readiness, None => std::process::abort() };
                    if !readiness.observe_once(descriptor, write, deadline) {
                        inner.observe_failed_hello_posts_once(original);
                        return self.close();
                    }
                    // The complete native poll/clock pass owns no fresh FD or
                    // borrowed record. Dispose its actual positive observation
                    // before entering another finite readiness wait.
                    drop(self.readiness.take());
                }
                Err(_) => {
                    inner.observe_failed_hello_posts_once(original);
                    return self.close();
                }
            }
        }
    }

    /// Transfers only the actual narrow Session after complete joint success.
    ///
    /// # Errors
    /// Refuses failure, missing completion or repeated consumption; old failed
    /// Session, native prefixes and boxed handshake originals never escape.
    #[doc(hidden)]
    pub fn take_completed_once(&mut self)
        -> Result<DormantAuthenticatedBrokerSessionV1, OriginalStorageClientTransitionClosedV1>
    {
        if self.closed.is_some() || self.readiness.is_some() { return self.close(); }
        let inner = match self.inner.as_mut() { Some(inner) => inner, None => return self.close() };
        match inner.take_completed_once() {
            Ok(session) => Ok(DormantAuthenticatedBrokerSessionV1(session, Vec::new())),
            Err(_) => self.close(),
        }
    }

    /// Rejoins this actual completed rollover before a separately funded purpose.
    ///
    /// The same current Preparation Session and initial capture remain held.
    /// This comparison neither retires its transport nor creates an Apply
    /// Session, Root authorization, request, lease or new financial owner.
    ///
    /// # Errors
    /// Retains the originating initial capture, rollover, same-C payment, or
    /// completed native Journal/socket/transcript association refusal.
    #[doc(hidden)]
    pub fn require_provisioning_predecessor_once_v1(
        &mut self,
        capture: &DormantControllerInitialSessionOpenV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        receiving: &mut aos_sandbox::OriginalCreateProvisioningRootLoanV1<'_, '_>,
        controller: &aos_sandbox::Journal,
        complete: aos_sandbox_core::ResourceVector,
    ) -> Result<(), OriginalStorageClientTransitionClosedV1> {
        if self.closed.is_some() || self.readiness.is_some()
            || self.provisioning_predecessor.is_some() || self.provisioning_lineage.is_some()
            || !session.1.is_empty()
        {
            return self.close();
        }
        let rollover = match self.inner.as_ref().and_then(|inner| inner.completed_rollover_v1()) {
            Some(rollover) => rollover,
            None => return self.close(),
        };
        let mut held = match capture.borrow_completed_preparation_kernel_session_v1(rollover, &mut session.0) {
            Ok(held) => {
                self.provisioning_lineage = Some(Ok(()));
                held
            }
            Err(cause) => {
                self.provisioning_lineage = Some(Err(cause));
                return self.close();
            }
        };
        let (initial, session) = held.reborrow_v1();
        self.provisioning_predecessor = Some(match session.require_create_provisioning_predecessor_v1(
            initial, receiving, controller, complete,
        ) {
            Ok(result) => result,
            Err(cause) => {
                self.provisioning_lineage = Some(Err(cause));
                return self.close();
            }
        });
        if !matches!(self.provisioning_predecessor, Some(Ok(()))) { return self.close(); }
        Ok(())
    }

    /// Borrows only this comparison's reached original financial cause.
    #[doc(hidden)]
    #[must_use]
    pub fn provisioning_predecessor_failure_v1<'cause>(
        &'cause self,
        receiving: &'cause aos_sandbox::CreateProvisioningOriginalsV1,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = &self.provisioning_lineage { return Some(cause); }
        if let Some(Err(cause)) = &self.provisioning_predecessor {
            return Some(cause.failure_with_original_v1(receiving));
        }
        self.failure_with_native_cause(None)
    }

    /// Borrows the chronological actual cause through the same resident scope.
    #[doc(hidden)]
    #[must_use]
    pub fn failure_with_ready<'cause>(
        &'cause self,
        ready: &'cause OriginalCreateStorageReadyV1<'_, '_>,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        self.failure_with_native_cause(ready.failure())
    }

    fn failure_with_native_cause<'cause>(
        &'cause self,
        native: Option<&'cause (dyn std::error::Error + 'static)>,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        // A readiness owner is present only while that primary observation
        // failed. Its owed posts run later and cannot replace this cause.
        self.readiness.as_ref().and_then(ReadinessOriginalV1::failure)
            .or_else(|| self.inner.as_ref().and_then(|inner| inner.failure_with_native_cause(native)))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn failed_real_readiness_keeps_its_cause_before_later_closure() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let deadline = crate::production_deadline_after(
            std::time::Duration::from_millis(10),
        ).unwrap();
        let mut readiness = ReadinessOriginalV1::default();

        assert!(!readiness.observe_once(socket.as_fd(), false, deadline));
        assert!(matches!(readiness.native, Some(Ok(0))));
        assert!(matches!(readiness.returned,
            Some(Err(DormantBrokerSessionHandshakeErrorV1::Deadline))));

        // This refusal-only diagnostic owner creates no Session or J loan.
        // It keeps the actual poll and timeout while a later closure is parked.
        let mut transition = OriginalStorageClientSessionTransitionV1 {
            old: None,
            inner: None,
            readiness: Some(readiness),
            host_tickets: None,
            closed: None,
            started: true,
            provisioning_predecessor: None,
            provisioning_lineage: None,
            provisioning_handoff_entered: false,
            provisioning_borrowed: None,
        };
        let first = transition.failure_with_native_cause(None).unwrap()
            .downcast_ref::<DormantBrokerSessionHandshakeErrorV1>().unwrap()
            as *const DormantBrokerSessionHandshakeErrorV1;
        transition.closed = Some(OriginalStorageClientTransitionClosedV1);
        let later = aos_sandbox::CreateStorageClientSessionClosedV1;

        assert_eq!(transition.failure_with_native_cause(Some(&later)).unwrap()
            .downcast_ref::<DormantBrokerSessionHandshakeErrorV1>().unwrap()
            as *const _, first);
        assert!(matches!(transition.readiness.as_ref().unwrap().native, Some(Ok(0))));
    }

    #[test]
    fn completed_readiness_slot_refuses_a_second_native_wait() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let deadline = crate::production_deadline_after(
            std::time::Duration::from_millis(10),
        ).unwrap();
        let mut readiness = ReadinessOriginalV1::default();
        assert!(!readiness.observe_once(socket.as_fd(), false, deadline));
        let first = readiness.failure().unwrap()
            .downcast_ref::<DormantBrokerSessionHandshakeErrorV1>().unwrap()
            as *const DormantBrokerSessionHandshakeErrorV1;

        // An expired caller value would produce another deadline if the native
        // helper ran. The already-complete slot returns before any new wait.
        assert!(!readiness.observe_once(socket.as_fd(), true, 0));

        assert_eq!(readiness.failure().unwrap()
            .downcast_ref::<DormantBrokerSessionHandshakeErrorV1>().unwrap()
            as *const _, first);
        assert!(matches!(readiness.native, Some(Ok(0))));
    }
}
