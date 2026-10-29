//! Bounded durable group commits with independent rollback for each retry wave.
//!
//! One blocking writer drains already queued work without waiting to fill a group.
//! Every successful wave waits for the same EXTRA commit and final custody check.
//! Savepoints keep a refused wave from leaving writes in a neighboring wave.

use std::collections::VecDeque;
use std::sync::Arc;

use rusqlite::{Transaction, TransactionBehavior};
use tokio::sync::{oneshot, OwnedSemaphorePermit};

use super::{DirectClientError, State};

/// Bounds queued and executing waves, each with its original payload limits.
pub(super) const MAX_PENDING_WAVES: usize = 8;

type Completion = Box<dyn FnOnce(Result<(), DirectClientError>) + Send>;
type Work = Box<dyn FnOnce(&Transaction<'_>) -> Outcome + Send>;

struct Pending {
    work: Work,
    _reservation: OwnedSemaphorePermit,
}

struct Outcome {
    successful: bool,
    complete: Completion,
}

/// Retains bounded pending work and the single blocking writer's ownership.
#[derive(Default)]
pub(super) struct Queue {
    pending: VecDeque<Pending>,
    running: bool,
}

/// Enqueues one bounded wave and waits until its group has committed durably.
///
/// # Errors
/// Returns the wave's validation error, or a checkpoint error for failed file
/// custody, SQLite transactions, queue ownership or writer completion.
pub(super) async fn submit<T: Send + 'static>(
    state: Arc<State>,
    reservation: OwnedSemaphorePermit,
    work: impl FnOnce(&Transaction<'_>) -> Result<T, DirectClientError> + Send + 'static,
) -> Result<T, DirectClientError> {
    let (send, receive) = oneshot::channel();
    let pending = Pending {
        work: Box::new(move |transaction| {
            let result = work(transaction);
            Outcome {
                successful: result.is_ok(),
                complete: Box::new(move |committed| {
                    let _ = send.send(committed.and(result));
                }),
            }
        }),
        _reservation: reservation,
    };

    let start_writer = {
        let mut queue = state
            .waves
            .lock()
            .map_err(|_| DirectClientError::Checkpoint)?;
        queue.pending.push_back(pending);
        let start = !queue.running;
        queue.running = true;
        start
    };
    if start_writer {
        // Dropping a waiter must not cancel a wave already submitted for custody.
        tokio::task::spawn_blocking(move || drain(state));
    }
    receive.await.map_err(|_| DirectClientError::Checkpoint)?
}

/// Releases queued waiters if the blocking writer unwinds unexpectedly.
struct Writer {
    state: Arc<State>,
    active: bool,
}

impl Drop for Writer {
    fn drop(&mut self) {
        if self.active {
            let mut queue = match self.state.waves.lock() {
                Ok(queue) => queue,
                Err(error) => error.into_inner(),
            };
            queue.running = false;
            queue.pending.clear();
        }
    }
}

fn drain(state: Arc<State>) {
    let mut writer = Writer {
        state,
        active: true,
    };
    loop {
        let group = {
            let Ok(mut queue) = writer.state.waves.lock() else {
                return;
            };
            if queue.pending.is_empty() {
                queue.running = false;
                writer.active = false;
                return;
            }
            queue.pending.drain(..).collect::<Vec<_>>()
        };
        execute_group(&writer.state, group);
    }
}

fn execute_group(state: &State, group: Vec<Pending>) {
    let mut outcomes = Vec::with_capacity(group.len());
    // Retain every reservation until all results have passed the durability fence.
    let mut reservations = Vec::with_capacity(group.len());
    let committed = (|| {
        state.file.verify()?;
        let mut connection = state
            .connection
            .lock()
            .map_err(|_| DirectClientError::Checkpoint)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| DirectClientError::Checkpoint)?;
        for pending in group {
            reservations.push(pending._reservation);
            transaction
                .execute_batch("SAVEPOINT checkpoint_wave")
                .map_err(|_| DirectClientError::Checkpoint)?;
            let outcome = (pending.work)(&transaction);
            let successful = outcome.successful;
            outcomes.push(outcome);
            if !successful {
                transaction
                    .execute_batch("ROLLBACK TO checkpoint_wave")
                    .map_err(|_| DirectClientError::Checkpoint)?;
            }
            transaction
                .execute_batch("RELEASE checkpoint_wave")
                .map_err(|_| DirectClientError::Checkpoint)?;
        }
        state.file.verify()?;
        transaction
            .commit()
            .map_err(|_| DirectClientError::Checkpoint)?;
        state.file.verify()
    })();

    for outcome in outcomes {
        (outcome.complete)(committed);
    }
}

#[cfg(test)]
mod tests;
