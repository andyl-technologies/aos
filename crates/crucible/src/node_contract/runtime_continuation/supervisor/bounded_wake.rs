//! Owns a concrete notification allocation without retaining an executor task.
//!
//! The event counter carries cleanup wakeups only. It is neither simulation time
//! nor a native readiness, execution or reclamation receipt. The separate reader
//! waits synchronously with a bounded operational fallback on the owning thread.

use std::{
    os::fd::OwnedFd,
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering},
    },
    task::{Wake, Waker},
    time::Duration,
};

use super::*;
use rustix::{
    event::{EventfdFlags, PollFd, PollFlags, Timespec},
    io::Errno,
};

pub(super) struct CustodyNotifier {
    process: u32,
    fd: OwnedFd,
    fault: AtomicI32,
}

impl CustodyNotifier {
    fn notify(&self) {
        // Waker is Send within this process. An inherited fork alias must not
        // write the original process's notification descriptor.
        if self.process != std::process::id() {
            return;
        }
        // NONBLOCK bounds each write. An already-full counter is readable and
        // preserves the coalesced wake. Exhausted interrupt retries are sticky;
        // the external driver still performs its finite timeout fallback.
        for _ in 0..2 {
            match rustix::io::write(&self.fd, &1u64.to_ne_bytes()) {
                Ok(8) | Err(Errno::AGAIN) => return,
                Err(Errno::INTR) => continue,
                Ok(_) => {
                    self.remember(Errno::IO);
                    return;
                }
                Err(error) => {
                    self.remember(error);
                    return;
                }
            }
        }
        self.remember(Errno::INTR);
    }

    fn remember(&self, error: Errno) {
        let _ = self.fault.compare_exchange(
            0,
            error.raw_os_error(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

impl Wake for CustodyNotifier {
    fn wake(self: Arc<Self>) {
        self.notify();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.notify();
    }
}

/// Retains the selected original cleanup event counter outside the runtime.
///
/// The reader is not cloneable and owns a separate descriptor for the same
/// kernel event counter. Neither descriptor retains a task, callback or native
/// capsule. Its kernel resources require independent admission; this object's
/// requested Rust allocation facts do not describe kernel memory or physical RSS.
pub struct RuntimeCustodyWakeReader {
    notifier: Arc<CustodyNotifier>,
    waker: Waker,
    reader: OwnedFd,
    process: u32,
    thread: std::thread::ThreadId,
}

/// Describes notification transport observations without native progress credit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeCustodyWakeWait {
    /// An actual event counter was consumed; cleanup must be polled again.
    Notified,
    /// The operational timeout elapsed; cleanup must be polled again.
    Fallback,
    /// An interrupt ended the wait; cleanup must be polled again.
    Interrupted,
    /// A sticky transport fault remains while original cleanup custody is held.
    Fault(i32),
}

impl RuntimeCustodyWakeReader {
    pub(super) fn create() -> Result<Self, RuntimeError> {
        let fd = rustix::event::eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let reader =
            rustix::io::fcntl_dupfd_cloexec(&fd, 0).map_err(|_| RuntimeError::ResourceLimit)?;
        let notifier = Arc::new(CustodyNotifier {
            process: std::process::id(),
            fd,
            fault: AtomicI32::new(0),
        });
        // Separate From<Arc<_>> sites may produce different RawWaker vtables.
        // Retain this representation and clone it at every selected boundary.
        let waker = Waker::from(Arc::clone(&notifier));
        Ok(Self {
            notifier,
            waker,
            reader,
            process: std::process::id(),
            thread: std::thread::current().id(),
        })
    }

    pub(super) fn original(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.notifier.process != self.process {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Clones this same concrete cleanup waker without capturing an executor.
    ///
    /// This notification handle issues no native or runtime permission. Its Arc
    /// backing stays alive until all original cleanup aliases are released.
    ///
    /// # Errors
    /// Refuses foreign creator process or thread before cloning the original Arc.
    pub fn original_cleanup_waker(&self) -> Result<Waker, RuntimeError> {
        self.original()?;
        Ok(self.waker.clone())
    }

    /// Waits once for cleanup notification with an independently bounded fallback.
    ///
    /// The timeout is operational host time, never a simulation coordinate. A
    /// signal or fault never authorizes releasing native/runtime custody. The
    /// caller polls the same original cleanup owner again after every result.
    ///
    /// # Errors
    /// Refuses a foreign creator or a timeout outside one to 100 milliseconds.
    pub fn wait(&self, maximum_wait: Duration) -> Result<RuntimeCustodyWakeWait, RuntimeError> {
        self.original()?;
        if maximum_wait < Duration::from_millis(1) || maximum_wait > Duration::from_millis(100) {
            return Err(RuntimeError::ResourceLimit);
        }
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: maximum_wait.subsec_nanos().into(),
        };
        let mut descriptors = [PollFd::new(&self.reader, PollFlags::IN)];
        let observed = match rustix::event::poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => RuntimeCustodyWakeWait::Fallback,
            Ok(_) => {
                let mut counter = [0u8; 8];
                match rustix::io::read(&self.reader, &mut counter) {
                    Ok(8) => RuntimeCustodyWakeWait::Notified,
                    Err(Errno::AGAIN) => RuntimeCustodyWakeWait::Fallback,
                    Err(Errno::INTR) => RuntimeCustodyWakeWait::Interrupted,
                    Ok(_) => {
                        self.notifier.remember(Errno::IO);
                        RuntimeCustodyWakeWait::Fault(Errno::IO.raw_os_error())
                    }
                    Err(error) => {
                        self.notifier.remember(error);
                        RuntimeCustodyWakeWait::Fault(error.raw_os_error())
                    }
                }
            }
            Err(Errno::INTR) => RuntimeCustodyWakeWait::Interrupted,
            Err(error) => {
                self.notifier.remember(error);
                RuntimeCustodyWakeWait::Fault(error.raw_os_error())
            }
        };
        self.original()?;
        let fault = self.notifier.fault.load(Ordering::Acquire);
        Ok(if fault == 0 {
            observed
        } else {
            RuntimeCustodyWakeWait::Fault(fault)
        })
    }

    /// Reports actual shared notifier requested storage, excluding this inline reader.
    ///
    /// The queue and reader may conservatively charge the same notifier per view;
    /// equal identifiers never establish an allocation-identity refund.
    ///
    /// # Errors
    /// Refuses foreign origin, arithmetic overflow or insufficient byte credit.
    pub fn retained_requested_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        self.original()?;
        notifier_requested(&self.notifier, maximum)
    }
}

pub(super) fn notifier_requested(
    value: &Arc<CustodyNotifier>,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let header = crate::node_contract::NodeRuntime::capture_protocol_shared_header_storage(
        1,
        std::mem::align_of_val(value.as_ref()),
        maximum,
    )?;
    std::mem::size_of_val(value.as_ref())
        .checked_add(header)
        .filter(|bytes| *bytes <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}

impl RuntimeCustodyQueue {
    /// Preallocates a selected queue and concrete bounded wake transport before birth.
    ///
    /// This fixes only cleanup notification ownership. It creates no activation,
    /// readiness or native permission. The caller retains the reader through all
    /// refusal/cancellation paths and drives the same queue until real reclamation.
    ///
    /// # Errors
    /// Refuses unavailable queue, descriptor or finite host allocation resources.
    pub fn new_with_bounded_wake(
        maximum_worlds: usize,
    ) -> Result<(Self, RuntimeCustodyWakeReader), RuntimeError> {
        let mut queue = Self::new(maximum_worlds)?;
        let reader = RuntimeCustodyWakeReader::create()?;
        let inner = Rc::get_mut(&mut queue.inner).ok_or(RuntimeError::OutstandingObligations)?;
        inner.notifier = Some(Arc::clone(&reader.notifier));
        inner.original_waker = Some(reader.waker.clone());
        Ok((queue, reader))
    }

    /// Polls actual cleanup using this queue's same original concrete wake owner.
    ///
    /// A foreign reader cannot substitute a new notification allocation. Ordinary
    /// caller-context polling remains separate and may retain unknown task backing.
    ///
    /// # Errors
    /// Refuses a foreign creator/reader before polling or changing the stored waker.
    pub fn poll_reclamation_with_original_wake(
        &self,
        reader: &RuntimeCustodyWakeReader,
    ) -> Result<Poll<Result<(), crate::node_contract::RuntimePollFailure>>, RuntimeError> {
        reader.original()?;
        if self.inner.process != std::process::id()
            || self.inner.thread != std::thread::current().id()
            || !self
                .inner
                .notifier
                .as_ref()
                .is_some_and(|original| Arc::ptr_eq(original, &reader.notifier))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let waker = reader.original_cleanup_waker()?;
        let mut context = Context::from_waker(&waker);
        Ok(self.poll_reclamation(&mut context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait_transport(
        reader: &RuntimeCustodyWakeReader,
    ) -> Result<RuntimeCustodyWakeWait, RuntimeError> {
        for _ in 0..4 {
            let observed = reader.wait(Duration::from_millis(1))?;
            if observed != RuntimeCustodyWakeWait::Interrupted {
                return Ok(observed);
            }
        }
        Err(RuntimeError::OutstandingObligations)
    }

    #[test]
    fn selected_queue_foreign_origin_refuses_reservation_before_keepalive_borrow()
    -> Result<(), RuntimeError> {
        let (mut queue, _reader) = RuntimeCustodyQueue::new_with_bounded_wake(1)?;
        Rc::get_mut(&mut queue.inner)
            .ok_or(RuntimeError::OutstandingObligations)?
            .process = std::process::id().wrapping_add(1);
        let (runtime, source) = crate::node_contract::runtime::tests::capture_ticket_fixture();
        let proposal = crate::node_contract::ActivationRecord {
            generation: source.source_activation.generation,
            activation_id: source.source_activation.activation_id,
            world_binding_hash: source.source_activation.world_binding_hash,
            owners: source.source_activation.owners,
            boundary: source.source_activation.boundary,
        };
        let keepalive = queue.inner.keepalive.borrow_mut();
        assert!(matches!(
            queue.reserve_world(&proposal, runtime.limits),
            Err(RuntimeError::ForeignAuthority)
        ));
        assert!(keepalive.is_none());
        assert_eq!(queue.reserved_worlds(), 0);
        Ok(())
    }

    #[test]
    fn original_wake_before_wait_and_after_drain_is_not_lost_or_multiplied()
    -> Result<(), RuntimeError> {
        let (queue, reader) = RuntimeCustodyQueue::new_with_bounded_wake(1)?;
        let waker = reader.original_cleanup_waker()?;
        waker.wake_by_ref();
        waker.wake_by_ref();
        assert_eq!(wait_transport(&reader)?, RuntimeCustodyWakeWait::Notified);
        assert_eq!(wait_transport(&reader)?, RuntimeCustodyWakeWait::Fallback);
        waker.wake_by_ref();
        assert_eq!(wait_transport(&reader)?, RuntimeCustodyWakeWait::Notified);
        assert!(matches!(
            queue.poll_reclamation_with_original_wake(&reader)?,
            Poll::Ready(Ok(()))
        ));
        assert!(
            queue
                .retained_requested_storage_data(1024 * 1024)?
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn inherited_foreign_process_wake_cannot_write_original_event_counter()
    -> Result<(), RuntimeError> {
        let RuntimeCustodyWakeReader {
            mut notifier,
            waker,
            reader,
            process,
            thread,
        } = RuntimeCustodyWakeReader::create()?;
        // Remove the original clone before modeling an inherited creator. The
        // production transport never mutates or replaces its notifier owner.
        drop(waker);
        Arc::get_mut(&mut notifier)
            .ok_or(RuntimeError::OutstandingObligations)?
            .process = std::process::id().wrapping_add(1);
        let reader = RuntimeCustodyWakeReader {
            waker: Waker::from(Arc::clone(&notifier)),
            notifier,
            reader,
            process,
            thread,
        };
        reader.waker.wake_by_ref();
        let mut bytes = [0u8; 8];
        assert_eq!(
            rustix::io::read(&reader.reader, &mut bytes),
            Err(Errno::AGAIN)
        );
        assert!(matches!(
            reader.original_cleanup_waker(),
            Err(RuntimeError::ForeignAuthority)
        ));
        assert_eq!(reader.notifier.fault.load(Ordering::Acquire), 0);
        Ok(())
    }

    #[test]
    fn saturated_event_counter_coalesces_without_sticky_failure() -> Result<(), RuntimeError> {
        let (_queue, reader) = RuntimeCustodyQueue::new_with_bounded_wake(1)?;
        rustix::io::write(&reader.notifier.fd, &(u64::MAX - 1).to_ne_bytes())
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        reader.original_cleanup_waker()?.wake_by_ref();
        assert_eq!(reader.notifier.fault.load(Ordering::Acquire), 0);
        assert_eq!(wait_transport(&reader)?, RuntimeCustodyWakeWait::Notified);
        Ok(())
    }

    #[test]
    fn foreign_reader_and_waker_refuse_without_replacing_original_transport()
    -> Result<(), RuntimeError> {
        let (queue, reader) = RuntimeCustodyQueue::new_with_bounded_wake(1)?;
        let (_foreign_queue, foreign) = RuntimeCustodyQueue::new_with_bounded_wake(1)?;
        assert!(matches!(
            queue.poll_reclamation_with_original_wake(&foreign),
            Err(RuntimeError::ForeignAuthority)
        ));
        let foreign_waker = foreign.original_cleanup_waker()?;
        let mut context = Context::from_waker(&foreign_waker);
        assert!(matches!(
            queue.poll_reclamation(&mut context),
            Poll::Ready(Err(crate::node_contract::RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority
            )))
        ));
        assert!(queue.inner.waker.borrow().is_none());
        assert!(matches!(
            queue.poll_reclamation_with_original_wake(&reader)?,
            Poll::Ready(Ok(()))
        ));
        let expected = reader.original_cleanup_waker()?;
        assert!(
            queue
                .inner
                .waker
                .borrow()
                .as_ref()
                .is_some_and(|held| held.will_wake(&expected))
        );
        for _ in 0..3 {
            let cloned = reader.original_cleanup_waker()?;
            assert!(cloned.will_wake(&expected));
            let mut context = Context::from_waker(&cloned);
            assert!(matches!(
                queue.poll_reclamation(&mut context),
                Poll::Ready(Ok(()))
            ));
            assert!(
                queue
                    .retained_requested_storage_data(1024 * 1024)?
                    .is_some()
            );
        }
        assert!(matches!(
            queue.poll_reclamation_with_original_wake(&foreign),
            Err(RuntimeError::ForeignAuthority)
        ));
        let mut context = Context::from_waker(&foreign_waker);
        assert!(matches!(
            queue.poll_reclamation(&mut context),
            Poll::Ready(Err(crate::node_contract::RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority
            )))
        ));
        assert!(
            queue
                .inner
                .waker
                .borrow()
                .as_ref()
                .is_some_and(|held| held.will_wake(&expected))
        );
        Ok(())
    }

    #[test]
    fn sticky_transport_failure_does_not_revoke_or_release_original_queue()
    -> Result<(), RuntimeError> {
        let (queue, reader) = RuntimeCustodyQueue::new_with_bounded_wake(1)?;
        reader.notifier.remember(Errno::INTR);
        reader.notifier.remember(Errno::IO);
        assert_eq!(
            reader.wait(Duration::from_millis(1))?,
            RuntimeCustodyWakeWait::Fault(Errno::INTR.raw_os_error())
        );
        assert_eq!(queue.reserved_worlds(), 0);
        assert!(matches!(
            queue.poll_reclamation_with_original_wake(&reader)?,
            Poll::Ready(Ok(()))
        ));
        assert_eq!(
            reader.notifier.fault.load(Ordering::Acquire),
            Errno::INTR.raw_os_error()
        );
        Ok(())
    }

    #[test]
    fn concrete_wake_alias_keeps_original_owned_fd_until_last_cleanup_alias_drops()
    -> Result<(), RuntimeError> {
        let (queue, reader) = RuntimeCustodyQueue::new_with_bounded_wake(1)?;
        let weak = Arc::downgrade(&reader.notifier);
        let waker = reader.original_cleanup_waker()?;
        let original_flags = rustix::io::fcntl_getfd(&reader.notifier.fd)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let reader_flags =
            rustix::io::fcntl_getfd(&reader.reader).map_err(|_| RuntimeError::InvalidReceipt)?;
        assert!(original_flags.contains(rustix::io::FdFlags::CLOEXEC));
        assert!(reader_flags.contains(rustix::io::FdFlags::CLOEXEC));
        drop(reader);
        drop(queue);
        assert!(weak.upgrade().is_some());
        // The same fd remains safely usable while this known wake alias owns it.
        waker.wake_by_ref();
        drop(waker);
        assert!(weak.upgrade().is_none());
        Ok(())
    }
}

impl RuntimeCustodyQueue {
    /// Counts the two descriptors of this queue's exact bounded wake transport.
    ///
    /// This authenticates the same original queue/notifier/reader association.
    /// A reserved empty slot owns no further descriptors; retained runtime
    /// custody is unsupported here and cannot be interpreted as empty.
    ///
    /// # Errors
    /// Refuses foreign or unrelated transport, busy/retained runtime custody,
    /// an unsupported waker or changed shared queue ownership.
    pub fn retained_descriptor_count_with_original_reader_data(
        &self,
        reader: &RuntimeCustodyWakeReader,
    ) -> Result<usize, RuntimeError> {
        reader.original()?;
        if self.inner.process != std::process::id()
            || self.inner.thread != std::thread::current().id()
            || !self
                .inner
                .notifier
                .as_ref()
                .is_some_and(|notifier| Arc::ptr_eq(notifier, &reader.notifier))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let waker = self
            .inner
            .waker
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if waker
            .as_ref()
            .is_some_and(|waker| !waker.will_wake(&reader.waker))
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let keepalive = self
            .inner
            .keepalive
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if keepalive
            .as_ref()
            .is_some_and(|owner| !Rc::ptr_eq(owner, &self.inner))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        for mailbox in &self.inner.mailboxes {
            if mailbox.polling.get()
                || mailbox
                    .custody
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .is_some()
            {
                return Err(RuntimeError::UnsupportedFacet);
            }
        }
        // CustodyNotifier owns its eventfd; this same reader owns its dup.
        // Arc and Waker aliases retain the first fd without creating more fds.
        Ok(2)
    }
}

#[cfg(test)]
mod descriptor_count_tests {
    use super::*;

    #[test]
    fn descriptor_count_requires_the_same_real_queue_and_reader() {
        let (queue, reader) = RuntimeCustodyQueue::new_with_bounded_wake(1).unwrap();
        let (other, other_reader) = RuntimeCustodyQueue::new_with_bounded_wake(1).unwrap();

        assert_eq!(
            queue.retained_descriptor_count_with_original_reader_data(&reader),
            Ok(2)
        );
        assert_eq!(
            other.retained_descriptor_count_with_original_reader_data(&other_reader),
            Ok(2)
        );
        assert!(
            queue
                .retained_descriptor_count_with_original_reader_data(&other_reader)
                .is_err()
        );
        assert!(
            other
                .retained_descriptor_count_with_original_reader_data(&reader)
                .is_err()
        );
        assert_eq!(queue.reserved_worlds(), 0);
        assert_eq!(other.reserved_worlds(), 0);
    }
}

// The actual notifier owns exactly one writer OwnedFd; the independently held
// wake reader's duplicate is counted by the same complete supervisor row.
pub(super) fn notifier_descriptor_count_data(
    notifier: &CustodyNotifier,
) -> Result<usize, RuntimeError> {
    use std::os::fd::AsRawFd;
    let CustodyNotifier {
        process,
        fd,
        fault: _,
    } = notifier;
    if *process != std::process::id() {
        return Err(RuntimeError::ForeignAuthority);
    }
    if fd.as_raw_fd() < 0 {
        return Err(RuntimeError::OwnerUnavailable);
    }
    Ok(1)
}
