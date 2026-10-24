//! Concrete finite teardown producer custody for the private effect-owner stage.
//!
//! The selected original-role profile uses three preallocated trigger credits.
//! A received trigger remains charged in its actual queue until the same worker
//! enters modeled admission. Legacy installation and hot-fork paths retain their
//! original channels. This prototype does not register semantic input closure or
//! grant an epoch, native effect permission, capture or Ready.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, TryLockError, mpsc};

use super::bounded_original::{BoundedOriginalMailbox, MailboxRefusal, SubmissionRefusal};
use super::{LiveRuntimeTeardownTrigger, PluginArgs, PluginRuntimeInstallError};

const MAXIMUM_DIAGNOSTIC_BYTES: usize = 512;
const MAXIMUM_ORIGINAL_TRIGGERS: usize = 3;

/// Routes callbacks to the same current teardown allocation.
///
/// Legacy installation preserves its original blocking route mutex. The finite
/// selector uses try_lock and preserves a refused producer through fail-stop.
/// Hot-fork replacement is valid only beneath the existing callback/worker
/// barrier; it never changes a route while a callback can be using it.
pub(super) struct LiveRuntimeTeardownRouter {
    sender: Mutex<TeardownSender>,
    finite: AtomicBool,
    process_id: AtomicU32,
}

impl LiveRuntimeTeardownRouter {
    pub(super) fn new(sender: impl Into<TeardownSender>) -> Arc<Self> {
        let sender = sender.into();
        let finite = matches!(sender, TeardownSender::Bounded(_));
        Arc::new(Self {
            sender: Mutex::new(sender),
            finite: AtomicBool::new(finite),
            process_id: AtomicU32::new(std::process::id()),
        })
    }

    pub(super) fn is_original_finite(&self) -> bool {
        self.process_id.load(Ordering::Acquire) == std::process::id()
            && self.finite.load(Ordering::Acquire)
    }

    pub(super) fn send(&self, trigger: LiveRuntimeTeardownTrigger) -> Result<(), ()> {
        if self.finite.load(Ordering::Acquire) {
            return match self.try_send_bounded(trigger) {
                Ok(_) => Ok(()),
                Err(refused) => abort_retaining_payload(refused),
            };
        }
        self.sender
            .lock()
            .map_err(|_| ())?
            .send(trigger)
            .map_err(|_| ())
    }

    fn try_send_bounded(
        &self,
        trigger: LiveRuntimeTeardownTrigger,
    ) -> Result<u64, SubmissionRefusal<LiveRuntimeTeardownTrigger>> {
        if self.process_id.load(Ordering::Acquire) != std::process::id() {
            return Err(SubmissionRefusal {
                reason: MailboxRefusal::ForeignProcess,
                original: trigger,
            });
        }
        let sender = match self.sender.try_lock() {
            Ok(sender) => sender,
            Err(error) => {
                return Err(SubmissionRefusal {
                    reason: match error {
                        TryLockError::WouldBlock => MailboxRefusal::Busy,
                        TryLockError::Poisoned(_) => MailboxRefusal::Poisoned,
                    },
                    original: trigger,
                });
            }
        };
        sender.try_submit_original(trigger)
    }

    pub(super) fn replace(&self, sender: impl Into<TeardownSender>) -> Result<(), ()> {
        let mut current = self.sender.lock().map_err(|_| ())?;
        let sender = sender.into();
        let finite = matches!(sender, TeardownSender::Bounded(_));
        *current = sender;
        self.process_id.store(std::process::id(), Ordering::Release);
        self.finite.store(finite, Ordering::Release);
        Ok(())
    }
}

/// Retains either the unchanged legacy sender or the selected finite allocation.
#[derive(Clone)]
pub(super) enum TeardownSender {
    Legacy(mpsc::Sender<LiveRuntimeTeardownTrigger>),
    Bounded(Arc<BoundedOriginalMailbox<LiveRuntimeTeardownTrigger>>),
}

/// Retains the actual receiver allocation, with no second draining intermediary.
pub(super) enum TeardownReceiver {
    Legacy(mpsc::Receiver<LiveRuntimeTeardownTrigger>),
    Bounded(Arc<BoundedOriginalMailbox<LiveRuntimeTeardownTrigger>>),
}

/// Identifies the same received trigger without releasing its bounded credit.
pub(super) enum RetainedTrigger {
    Legacy(LiveRuntimeTeardownTrigger),
    Bounded(u64),
}

impl From<mpsc::Sender<LiveRuntimeTeardownTrigger>> for TeardownSender {
    fn from(sender: mpsc::Sender<LiveRuntimeTeardownTrigger>) -> Self {
        Self::Legacy(sender)
    }
}

impl From<mpsc::Receiver<LiveRuntimeTeardownTrigger>> for TeardownReceiver {
    fn from(receiver: mpsc::Receiver<LiveRuntimeTeardownTrigger>) -> Self {
        Self::Legacy(receiver)
    }
}

/// Reserves bounded payload slots before callback-addressable state is installed.
///
/// # Errors
/// Refuses finite allocation failure before publishing a runtime or native role.
pub(super) fn for_installation(
    args: &PluginArgs,
) -> Result<(TeardownSender, TeardownReceiver), PluginRuntimeInstallError> {
    if !args
        .native_node_control()
        .is_some_and(|config| config.bounded_teardown_version().is_some())
    {
        let (sender, receiver) = mpsc::channel();
        return Ok((sender.into(), receiver.into()));
    }
    let original = Arc::new(
        BoundedOriginalMailbox::new(MAXIMUM_ORIGINAL_TRIGGERS).map_err(|_| {
            PluginRuntimeInstallError::RootRunControl {
                source: std::io::Error::other("finite original teardown credit unavailable"),
            }
        })?,
    );
    Ok((
        TeardownSender::Bounded(Arc::clone(&original)),
        TeardownReceiver::Bounded(original),
    ))
}

fn diagnostic_fits(trigger: &LiveRuntimeTeardownTrigger) -> bool {
    match trigger {
        LiveRuntimeTeardownTrigger::RunControlFault { diagnostic } => {
            diagnostic.len() <= MAXIMUM_DIAGNOSTIC_BYTES
                && diagnostic.capacity() <= MAXIMUM_DIAGNOSTIC_BYTES
        }
        LiveRuntimeTeardownTrigger::HostQuit(_) | LiveRuntimeTeardownTrigger::SharedShutdown(_) => {
            true
        }
    }
}

impl TeardownSender {
    /// Publishes one original trigger without waiting for bounded receiver credit.
    ///
    /// A finite refusal keeps the exact payload alive through process abort. The
    /// callback cannot proceed after losing a mandatory teardown proof. This is
    /// containment of unknown custody, never a successful teardown disposition.
    ///
    /// # Errors
    /// Preserves the legacy disconnected-sender result on unchanged installations.
    pub(super) fn send(
        &self,
        trigger: LiveRuntimeTeardownTrigger,
    ) -> Result<(), mpsc::SendError<LiveRuntimeTeardownTrigger>> {
        match self {
            Self::Legacy(sender) => sender.send(trigger),
            Self::Bounded(_) => match self.try_submit_original(trigger) {
                Ok(_) => Ok(()),
                Err(refused) => abort_retaining_payload(refused),
            },
        }
    }

    /// Returns the exact owned original on every refused finite submission.
    ///
    /// # Errors
    /// Refuses unsupported diagnostic extent, busy/poisoned custody, foreign
    /// process, finite credit exhaustion or monotone identity exhaustion.
    fn try_submit_original(
        &self,
        trigger: LiveRuntimeTeardownTrigger,
    ) -> Result<u64, SubmissionRefusal<LiveRuntimeTeardownTrigger>> {
        let Self::Bounded(original) = self else {
            return Err(SubmissionRefusal {
                reason: MailboxRefusal::ForeignSequence,
                original: trigger,
            });
        };
        if !diagnostic_fits(&trigger) {
            return Err(SubmissionRefusal {
                reason: MailboxRefusal::CreditExhausted,
                original: trigger,
            });
        }
        original.try_submit(trigger)
    }
}

/// Retains the refused producer while its calling sender keeps the queue owned.
fn abort_retaining_payload(refused: SubmissionRefusal<LiveRuntimeTeardownTrigger>) -> ! {
    let SubmissionRefusal { reason, original } = refused;
    let _retained_original = std::mem::ManuallyDrop::new((reason, original));
    // This producer may own BQL. Even a short stderr diagnostic could wait for
    // another thread's lock or a full pipe, preventing mandatory containment.
    // Abort runs neither Rust destructors nor QEMU exit notifiers. The host must
    // reap the actual child and retain the original operation as effects unknown.
    std::process::abort()
}

impl TeardownReceiver {
    /// Preserves only the unchanged legacy receive behavior.
    ///
    /// A bounded receiver must use receive_retained so its credit cannot be
    /// released before original modeled-worker admission.
    ///
    /// # Errors
    /// Refuses legacy disconnect and any attempt to use this lane for finite data.
    pub(super) fn recv(&self) -> Result<LiveRuntimeTeardownTrigger, mpsc::RecvError> {
        match self {
            Self::Legacy(receiver) => receiver.recv(),
            Self::Bounded(_) => Err(mpsc::RecvError),
        }
    }

    /// Retains the first actual trigger without releasing finite producer credit.
    ///
    /// # Errors
    /// Refuses disconnected legacy producers or failed finite queue lifetime.
    pub(super) fn receive_retained(&self) -> Result<RetainedTrigger, mpsc::RecvError> {
        match self {
            Self::Legacy(receiver) => receiver.recv().map(RetainedTrigger::Legacy),
            Self::Bounded(original) => original
                .receive_original()
                .map(RetainedTrigger::Bounded)
                .map_err(|_| mpsc::RecvError),
        }
    }

    /// Takes the same bounded payload after the caller's real modeled gate entry.
    ///
    /// The sequence correlates storage only. InstalledTeardownMailbox verifies
    /// original lifetime; its worker separately obtains actual admission.
    ///
    /// # Errors
    /// Refuses busy/poisoned custody, foreign sequence or an incorrect channel lane.
    pub(super) fn take_bounded(
        &self,
        sequence: u64,
    ) -> Result<LiveRuntimeTeardownTrigger, MailboxRefusal> {
        match self {
            Self::Bounded(original) if original.lifetime_valid() => {
                original.take_received(sequence)
            }
            Self::Bounded(_) => Err(MailboxRefusal::Poisoned),
            Self::Legacy(_) => Err(MailboxRefusal::ForeignSequence),
        }
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Real queue and held-worker invariants deliberately panic on divergence.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "teardown_channel_tests.rs"]
mod tests;
