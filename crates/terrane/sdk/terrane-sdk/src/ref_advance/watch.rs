//! Polls authoritative committed horizons with current-policy checks and exact log gap filling.

use std::time::Duration;

use terrane_format::auth::Verb;
use terrane_format::refs::{RefClass, RefLogRecord, RefName, RefRecord};

use super::{AdvanceError, Coordinator};
use crate::store::{Clock, CorruptSubject, RefWatch, Store, StoreErrorKind, StoreFailure};

/// Requires shared clock access only when asynchronous operations must be sendable.
#[cfg(feature = "send")]
pub trait WatchClock: Clock + Sync {}

#[cfg(feature = "send")]
impl<C: Clock + Sync> WatchClock for C {}

/// Permits local clock bindings when asynchronous operations need not be sendable.
#[cfg(not(feature = "send"))]
pub trait WatchClock: Clock {}

#[cfg(not(feature = "send"))]
impl<C: Clock> WatchClock for C {}

/// Retains an authorized live ref subscription whose idle state never means closure.
pub struct GuardedWatch<'a, S, C, F> {
    coordinator: &'a Coordinator<S, C, F>,
    reference: String,
    token: Vec<u8>,
    surface: String,
    next_sequence: Option<u64>,
    closed: bool,
}

// A pending event is untrusted output until the same whole horizon survives
// closing authorization. It cannot advance the cursor or authorize later I/O.
struct PendingEvent {
    record: RefLogRecord,
    horizon: RefRecord,
}

impl<S: Store, C: Clock, F> Coordinator<S, C, F> {
    /// Opens a live branch watch that emits the current record before future successors.
    ///
    /// # Errors
    /// Rejects non-branch refs or unavailable current token and ACL authority.
    pub async fn watch(
        &self,
        reference: &str,
        token: &[u8],
        surface: &str,
    ) -> Result<GuardedWatch<'_, S, C, F>, AdvanceError> {
        let name = RefName::parse(reference).map_err(|_| AdvanceError::InvalidRefClass)?;
        if !matches!(
            name.class(),
            RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
        ) {
            return Err(AdvanceError::InvalidRefClass);
        }
        let authorized = self
            .guard()
            .authorize(reference, token, Verb::Read, &[], surface)
            .await?;
        Ok(GuardedWatch {
            coordinator: self,
            reference: reference.to_owned(),
            token: token.to_vec(),
            surface: surface.to_owned(),
            next_sequence: Some(authorized.record().map_or(1, |record| record.seq)),
            closed: false,
        })
    }
}

impl<S: Store, C: WatchClock, F> GuardedWatch<'_, S, C, F> {
    /// Closes the subscription; its next read returns `None`.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Waits for the next committed record while rechecking current authority.
    ///
    /// # Errors
    /// Returns denial after token expiry or ACL revocation, corruption for a
    /// committed sequence gap, and storage or clock errors without closing an
    /// otherwise live subscription. Authorization is checked again after log
    /// I/O. A changed whole head returns `Unavailable`; a refused attempt never
    /// advances the delivery cursor, so callers may retry the same sequence.
    pub async fn next(&mut self) -> Result<Option<RefLogRecord>, StoreFailure> {
        loop {
            if self.closed {
                return Ok(None);
            }
            if let Some(pending) = self.read_pending().await? {
                return self.emit(pending).await.map(Some);
            }
            self.coordinator
                .guard()
                .clock()
                .sleep(Duration::from_millis(10))
                .await
                .map_err(|error| {
                    let kind = if error.kind() == std::io::ErrorKind::Unsupported {
                        StoreErrorKind::Unsupported
                    } else {
                        StoreErrorKind::Unavailable { retry_after: None }
                    };
                    StoreFailure::with_source(kind, error)
                })?;
        }
    }

    async fn read_pending(&self) -> Result<Option<PendingEvent>, StoreFailure> {
        let authorized = self
            .coordinator
            .guard()
            .authorize(&self.reference, &self.token, Verb::Read, &[], &self.surface)
            .await?;
        let Some(head) = authorized.record() else {
            return Ok(None);
        };
        let sequence = self.next_sequence.unwrap_or(head.seq);
        if sequence > head.seq {
            return Ok(None);
        }

        let records = self
            .coordinator
            .store()
            .ref_log_read(&self.reference, sequence)
            .await?;
        let record = records
            .into_iter()
            .find(|record| record.record.seq == sequence)
            .ok_or_else(|| self.corrupt())?;
        if record.record.home != head.home || (sequence == head.seq && record.record != *head) {
            return Err(self.corrupt());
        }

        Ok(Some(PendingEvent {
            record,
            horizon: head.clone(),
        }))
    }

    async fn emit(&mut self, pending: PendingEvent) -> Result<RefLogRecord, StoreFailure> {
        // Reflog I/O can outlive token authority or race a policy/head change.
        // Refuse the entire attempt before exposing an entry or moving its
        // cursor; the same sequence remains available to a fresh retry.
        let current = self
            .coordinator
            .guard()
            .authorize(&self.reference, &self.token, Verb::Read, &[], &self.surface)
            .await?;
        if current.record() != Some(&pending.horizon) {
            return Err(StoreFailure::new(StoreErrorKind::Unavailable {
                retry_after: None,
            }));
        }
        let next_sequence = pending
            .record
            .record
            .seq
            .checked_add(1)
            .ok_or_else(|| self.corrupt())?;
        self.next_sequence = Some(next_sequence);
        Ok(pending.record)
    }

    fn corrupt(&self) -> StoreFailure {
        StoreFailure::new(StoreErrorKind::Corrupt(CorruptSubject::RefName(
            self.reference.clone(),
        )))
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<S: Store + Sync, C: Clock + Sync, F: Sync> RefWatch for GuardedWatch<'_, S, C, F> {
    async fn next(&mut self) -> Result<Option<RefLogRecord>, StoreFailure> {
        GuardedWatch::next(self).await
    }
}

#[cfg(all(test, feature = "tokio", unix))]
mod tests;
