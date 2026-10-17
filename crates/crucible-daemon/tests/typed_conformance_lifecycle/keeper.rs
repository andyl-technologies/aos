//! Keeps the complete original invocation through unwind and authentic retirement.
//!
//! The same owner stays outside every callback. Unknown does not return, release
//! a slot or become cleanup. Drop services original retirement before releasing
//! the holder; process abort/forced termination is outside Rust unwind custody.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    task::{Context, Poll, Waker},
};

use crucible_daemon::node_observed_executor::{
    PreparedTypedReaderHostInvocation, ReclaimedTypedReaderHostSources,
    StoredTypedReaderResultPublisher, StoredWorldActivationPublisher, TypedReaderCustodySupervisor,
    TypedReaderHostSourcesExecution,
};
use crucible_node_provider::client::ExchangeDeadline;

type Execution<'a> = TypedReaderHostSourcesExecution<
    'a,
    StoredWorldActivationPublisher,
    StoredTypedReaderResultPublisher,
>;
type Reclaimed<'a> = ReclaimedTypedReaderHostSources<
    'a,
    StoredWorldActivationPublisher,
    StoredTypedReaderResultPublisher,
>;

pub(super) struct WholeOriginal<'a> {
    prepared: Option<PreparedTypedReaderHostInvocation<'a>>,
    execution: Option<Execution<'a>>,
    failure: Option<crucible_daemon::node_observed_executor::TypedReaderHostInvocationFailure<'a>>,
    reclaimed: Option<Reclaimed<'a>>,
    supervisor: TypedReaderCustodySupervisor,
    waker: Waker,
    cadence: ExchangeDeadline,
    complete: bool,
    callback_unwound: bool,
}

#[derive(Debug)]
struct CallbackUnwind;

#[derive(Debug)]
pub(super) enum KeeperRefusal {
    Unavailable,
    OriginalRefused,
    CallbackUnwound,
}

fn borrowed<T, R>(
    original: &mut T,
    callback: impl FnOnce(&mut T) -> R,
) -> Result<R, CallbackUnwind> {
    catch_unwind(AssertUnwindSafe(|| callback(original))).map_err(|_| CallbackUnwind)
}

impl<'a> WholeOriginal<'a> {
    pub(super) fn new(
        prepared: PreparedTypedReaderHostInvocation<'a>,
        waker: Waker,
        cadence: ExchangeDeadline,
    ) -> Self {
        let supervisor = prepared.supervisor().clone();
        Self {
            prepared: Some(prepared),
            execution: None,
            failure: None,
            reclaimed: None,
            supervisor,
            waker,
            cadence,
            complete: false,
            callback_unwound: false,
        }
    }

    pub(super) fn start(&mut self) -> Result<(), KeeperRefusal> {
        let Some(original) = self.prepared.as_mut() else {
            return Err(KeeperRefusal::Unavailable);
        };
        match borrowed(original, |owner| owner.instantiate_original()) {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(KeeperRefusal::OriginalRefused),
            Err(_) => {
                self.callback_unwound = true;
                return Err(KeeperRefusal::CallbackUnwound);
            }
        }
        // After successful borrowed preparation, start performs only fixed
        // moves into the original actor. No installed/native callback follows
        // this take; the same prepared reservation/publishers are transferred.
        let Some(original) = self.prepared.take() else {
            return Err(KeeperRefusal::Unavailable);
        };
        match original.start() {
            Ok(original) => {
                self.execution = Some(original);
                Ok(())
            }
            Err(original) => {
                // This cached successful preparation path cannot ordinarily
                // refuse, but its complete returned failure must still survive.
                // Keep it outside any callback and service it to whole Ready.
                self.failure = Some(original);
                self.reclaim();
                Err(KeeperRefusal::OriginalRefused)
            }
        }
    }

    pub(super) fn drive(&mut self) {
        while !self.complete {
            let waker = self.waker.clone();
            let mut context = Context::from_waker(&waker);
            let result = borrowed(&mut self.execution, |owner| {
                owner.as_mut().map(|original| original.poll(&mut context))
            });
            match result {
                Ok(Some(Poll::Ready(original))) => {
                    self.reclaimed = Some(original);
                    self.complete = true;
                }
                Ok(Some(Poll::Pending)) => super::service_pending(&self.cadence),
                _ => {
                    self.callback_unwound |= result.is_err();
                    self.reclaim();
                }
            }
        }
    }

    fn poll_supervisor(&mut self) -> bool {
        let waker = self.waker.clone();
        let mut context = Context::from_waker(&waker);
        let result = borrowed(&mut self.supervisor, |owner| {
            owner.poll_reclamation(&mut context)
        });
        self.callback_unwound |= result.is_err();
        matches!(result, Ok(Poll::Ready(Ok(()))))
    }

    pub(super) fn reclaim(&mut self) {
        if !self.complete {
            reclaim_until(
                self,
                |original| original.reclaim_step(),
                |original| super::service_pending(&original.cadence),
            );
        }
    }

    fn reclaim_step(&mut self) -> bool {
        if let Some(original) = self.prepared.as_mut() {
            let retired = borrowed(original, |owner| owner.retire_original());
            self.callback_unwound |= retired.is_err();
            let reclaimed = self.poll_supervisor();
            if matches!(retired, Ok(Ok(()))) && reclaimed {
                self.complete = true;
            }
        } else if let Some(original) = self.failure.as_mut() {
            let retired = borrowed(original, |owner| {
                owner
                    .original_mut()
                    .map(|failed| failed.original.retire_original())
            });
            self.callback_unwound |= retired.is_err();
            let reclaimed = self.poll_supervisor();
            if matches!(retired, Ok(Some(Ok(())))) && reclaimed {
                self.complete = true;
            }
        } else if self.execution.is_some() {
            let requested = borrowed(&mut self.execution, |owner| {
                if let Some(original) = owner {
                    original.retire_original();
                }
            });
            self.callback_unwound |= requested.is_err();
            let waker = self.waker.clone();
            let mut context = Context::from_waker(&waker);
            let polled = borrowed(&mut self.execution, |owner| {
                owner.as_mut().map(|original| original.poll(&mut context))
            });
            self.callback_unwound |= polled.is_err();
            if let Ok(Some(Poll::Ready(original))) = polled {
                self.reclaimed = Some(original);
                self.complete = true;
            }
        }
        self.complete
    }

    pub(super) fn with_reclaimed(
        &mut self,
        callback: impl FnOnce(&Reclaimed<'a>) -> Result<(), Box<dyn std::error::Error>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.callback_unwound {
            return Err(super::public_error(
                "original callback unwound; authentic cleanup retained",
            )
            .into());
        }
        let result = borrowed(&mut self.reclaimed, |owner| match owner.as_ref() {
            Some(original) => callback(original),
            None => Err(super::public_error("original reclaimed holder unavailable").into()),
        });
        result.map_err(|_| {
            super::public_error("original publication/assertion unwound after cleanup")
        })?
    }
}

impl Drop for WholeOriginal<'_> {
    fn drop(&mut self) {
        // Cancellation/error/unwind cannot drop the whole upper holder while
        // any original obligation is unresolved. Same cuts, no synthetic reap.
        self.reclaim();
    }
}

// Neither callback consumes the full upper owner. This same loop is used by
// cancellation Drop, preparation failure and actual lifecycle uncertainty.
fn reclaim_until<T>(
    original: &mut T,
    mut step: impl FnMut(&mut T) -> bool,
    mut wait: impl FnMut(&mut T),
) {
    loop {
        if matches!(borrowed(original, &mut step), Ok(true)) {
            break;
        }
        let _ = borrowed(original, &mut wait);
    }
}

#[cfg(test)]
#[path = "keeper_tests.rs"]
mod tests;
