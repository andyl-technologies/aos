//! Independent descriptor-bound pager control servicing.
//!
//! The controller never enters QEMU or waits for guest/RR/BQL locks. Dispatch
//! observes bounded snapshots or enqueues bounded engine commands. Quiescence
//! drains a complete record and preserves the parent's descriptor and sequence;
//! child reconstruction closes its inherited duplicate without socket shutdown.

use std::io::{self, Read, Write};
use std::os::fd::{IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::source::{SourceOperation, SourceOperationClass, SourceOperationFactory};

use crucible_protocol::ram_control::{
    RamControlError, RamControlOuterCap, RamControlPolicy, RamControlReply, RamControlRequest,
    RamControlResources, RamControlTarget, serve_ram_control_once,
};

/// Actual paging owner; methods must never wait for guest locks or backing I/O.
pub(crate) trait PagerControl: SourceOperationFactory + 'static {
    /// Returns the exact admitted target without guest locks or backing I/O.
    fn identity(&self) -> RamControlTarget;

    /// Publishes actual current-thread independent-control ownership natively.
    ///
    /// # Errors
    /// Refuses stale generations, closed actor admission, or native role failure.
    fn worker_enter(&self) -> io::Result<()>;

    /// Discharges this thread's native service role after its last record.
    ///
    /// # Errors
    /// Refuses uncertain ownership or a failed native role disposition.
    fn worker_exit(&self) -> io::Result<()>;

    fn apply(
        &self,
        expected_revision: u64,
        policy_revision: u64,
        reservation_revision: u64,
        policy: RamControlPolicy,
        resources: RamControlResources,
    ) -> RamControlReply;

    fn status(&self) -> RamControlReply;

    fn test_fault_actor(
        &self,
        entitlement: [u8; 32],
        worker_generation: u64,
        action: crucible_protocol::ram_control::RamControlFaultActorAction,
    ) -> RamControlReply;

    fn inventory_region(&self, topology_generation: u64, ordinal: u32) -> RamControlReply;

    fn grant_inventory(
        &self,
        topology_generation: u64,
        resources: RamControlResources,
        spill_quota_bytes: u64,
    ) -> RamControlReply;

    fn sync_outer_cap(&self, cap: RamControlOuterCap) -> RamControlReply;

    fn cancel(&self, operation_generation: u64) -> RamControlReply;
}

/// Parent-only stream state preserved at a complete request/reply boundary.
pub(crate) struct QuiescedRamControl {
    stream: UnixStream,
    session: [u8; 32],
    target: RamControlTarget,
    sequence: u64,
}

impl QuiescedRamControl {
    /// Transfers unique inherited close custody without shutting down the parent.
    pub(crate) fn into_inherited_descriptor(self) -> RawFd {
        self.stream.into_raw_fd()
    }
}

/// Owned control worker and its independent admission-stop signal.
///
/// Engine lifetime includes this thread in the native registry. Fork preparation
/// must stop and join it before freezing that registry. Only successful join
/// returns a reusable parent endpoint; partial-record failures refuse handoff.
pub(crate) struct PagerControlWorker {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<QuiescedRamControl, RamControlError>>>,
    ready: Receiver<io::Result<()>>,
}

impl PagerControlWorker {
    /// Starts the dispatcher with a fresh descriptor-authenticated session.
    pub(crate) fn start(
        stream: UnixStream,
        session: [u8; 32],
        target: RamControlTarget,
        controller: Arc<dyn PagerControl>,
    ) -> io::Result<Self> {
        Self::resume(
            QuiescedRamControl {
                stream,
                session,
                target,
                sequence: 0,
            },
            controller,
        )
    }

    /// Resumes the parent's complete stream state without resetting authority.
    pub(crate) fn resume(
        mut state: QuiescedRamControl,
        controller: Arc<dyn PagerControl>,
    ) -> io::Result<Self> {
        if state.session == [0; 32] || state.target != controller.identity() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pager setup authority mismatch",
            ));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let (ready_tx, ready) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("crucible-ram-control".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                if let Err(error) = controller.worker_enter() {
                    let _sent = ready_tx.send(Err(error));
                    return Err(io::Error::other("native control worker admission failed").into());
                }
                if ready_tx.send(Ok(())).is_err() {
                    controller.worker_exit()?;
                    return Err(io::Error::other("control readiness receiver absent").into());
                }
                let result = (|| {
                    let mut dispatch = |request| match request {
                        RamControlRequest::Hello | RamControlRequest::Status => controller.status(),
                        RamControlRequest::TestFaultActor {
                            entitlement,
                            worker_generation,
                            action,
                        } => controller.test_fault_actor(entitlement, worker_generation, action),
                        RamControlRequest::Apply {
                            expected_revision,
                            policy_revision,
                            reservation_revision,
                            resources,
                            policy,
                        } => controller.apply(
                            expected_revision,
                            policy_revision,
                            reservation_revision,
                            policy,
                            resources,
                        ),
                        RamControlRequest::InventoryRegion {
                            topology_generation,
                            ordinal,
                        } => controller.inventory_region(topology_generation, ordinal),
                        RamControlRequest::GrantInventory {
                            topology_generation,
                            resources,
                            spill_quota_bytes,
                        } => controller.grant_inventory(
                            topology_generation,
                            resources,
                            spill_quota_bytes,
                        ),
                        RamControlRequest::SyncOuterCap { cap } => controller.sync_outer_cap(cap),
                        RamControlRequest::Cancel {
                            operation_generation,
                        } => controller.cancel(operation_generation),
                    };
                    loop {
                        if worker_stop.load(Ordering::Acquire) {
                            return Ok(state);
                        }
                        // Admission polling occurs only between records. Once the first
                        // byte is consumed, drain or fail the entire record under its
                        // original total deadline; never forget a partial request.
                        state
                            .stream
                            .set_read_timeout(Some(Duration::from_millis(25)))?;
                        let mut first = [0; 1];
                        match state.stream.read(&mut first) {
                            Ok(0) => {
                                return Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "pager controller closed",
                                )
                                .into());
                            }
                            Ok(_) => {}
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::Interrupted
                                        | io::ErrorKind::WouldBlock
                                        | io::ErrorKind::TimedOut
                                ) =>
                            {
                                continue;
                            }
                            Err(error) => return Err(error.into()),
                        }
                        let mut record = RecordStream {
                            stream: &mut state.stream,
                            first: Some(first[0]),
                            // Control remains available for status, cancellation and
                            // cap-expiry containment after the execution cap ends.
                            operation: controller.begin(SourceOperationClass::Cleanup)?,
                        };
                        serve_ram_control_once(
                            &mut record,
                            state.session,
                            state.target,
                            &mut state.sequence,
                            &mut dispatch,
                        )?;
                        record.operation.complete()?;
                    }
                })();
                let exited = controller.worker_exit();
                match (result, exited) {
                    (Ok(state), Ok(())) => Ok(state),
                    (Err(error), _) => Err(error),
                    (Ok(_), Err(error)) => Err(error.into()),
                }
            })?;
        Ok(Self {
            stop,
            worker: Some(worker),
            ready,
        })
    }

    /// Waits for actual native actor publication under an original-start token.
    ///
    /// # Errors
    /// Refuses failed native worker admission or an expired readiness allowance.
    /// The caller retains this worker and join authority on every error.
    pub(crate) fn wait_ready(&self, operation: &dyn SourceOperation) -> io::Result<()> {
        loop {
            let slice = operation.wait_slice()?;
            match self.ready.try_recv() {
                Ok(result) => return result,
                Err(TryRecvError::Disconnected) => {
                    return Err(io::Error::other("control readiness authority closed"));
                }
                Err(TryRecvError::Empty) => {
                    std::thread::sleep(slice.min(Duration::from_millis(10)))
                }
            }
        }
    }

    /// Closes admission and transfers unique join authority without shutdown.
    ///
    /// The lifecycle owner polls join completion under its admitted fork budget;
    /// it must retain the handle on timeout instead of blocking under QEMU locks.
    pub(crate) fn stop(
        mut self,
    ) -> io::Result<JoinHandle<Result<QuiescedRamControl, RamControlError>>> {
        self.stop.store(true, Ordering::Release);
        self.worker.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "pager control already stopped")
        })
    }
}

impl Drop for PagerControlWorker {
    fn drop(&mut self) {
        // Explicit engine teardown retains join ownership through stop(). A
        // dropped owner still closes new admission without touching the shared
        // socket file description inherited by a potential parent process.
        self.stop.store(true, Ordering::Release);
    }
}

struct RecordStream<'a> {
    stream: &'a mut UnixStream,
    first: Option<u8>,
    operation: Box<dyn SourceOperation>,
}

impl RecordStream<'_> {
    fn remaining(&self) -> io::Result<Duration> {
        let slice = self.operation.wait_slice()?.min(Duration::from_millis(10));
        if slice.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "pager control record allowance expired",
            ));
        }
        Ok(slice)
    }
}

impl Read for RecordStream<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if let Some(first) = self.first.take() {
            output[0] = first;
            return Ok(1);
        }
        loop {
            self.stream.set_read_timeout(Some(self.remaining()?))?;
            match self.stream.read(output) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }
}

impl Write for RecordStream<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        loop {
            self.stream.set_write_timeout(Some(self.remaining()?))?;
            match self.stream.write(input) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests;
