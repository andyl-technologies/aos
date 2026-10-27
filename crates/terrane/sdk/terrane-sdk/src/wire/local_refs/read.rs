//! Rechecks request identity and repository policy around every awaited read.

use std::{sync::Arc, time::SystemTime};

use connectrpc::ConnectError;
use terrane_format::{auth, refs::RefRecord};

use crate::{
    repository::{Error, ListedRef, RefHistory, Repository},
    store::{Clock, LocalFs, RefInventory, Store, StoreErrorKind},
    wire::status::{Outcome, ProtocolError},
};

// The native SDK context is fixed by the service, never selected by a header.
pub(super) struct ReadRequest<S: Store, C: Clock, F: LocalFs> {
    pub(super) repository: Arc<Repository<S, C, F>>,
    pub(super) token: Arc<[u8]>,
    pub(super) trace: Arc<str>,
}

impl<S: Store, C: Clock, F: LocalFs> Clone for ReadRequest<S, C, F> {
    fn clone(&self) -> Self {
        Self {
            repository: self.repository.clone(),
            token: self.token.clone(),
            trace: self.trace.clone(),
        }
    }
}

impl<S: Store + RefInventory + Sync, C: Clock + Sync, F: LocalFs + Sync> ReadRequest<S, C, F> {
    // Authentication is independent of the repository's existence-hiding denial.
    // In particular, idle/empty stream completion cannot retain expired identity.
    pub(super) fn identity(&self) -> Result<(), ConnectError> {
        let guard = self.repository.coordinator().guard();
        let now = guard
            .clock()
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| protocol(Outcome::Transient(None), &self.trace))?
            .as_secs();
        auth::verify(&self.token, guard.keys(), now)
            .map(|_| ())
            .map_err(|_| protocol(Outcome::Unauthenticated, &self.trace))
    }

    pub(super) async fn head(&self, name: &str) -> Result<Option<RefRecord>, ConnectError> {
        self.identity()?;
        let result = self.repository.ref_head(name, &self.token, "sdk").await;
        self.identity()?;
        result.map_err(|error| repository_error(error, &self.trace))
    }

    pub(super) async fn listing(&self, pattern: &str) -> Result<Vec<ListedRef>, ConnectError> {
        self.identity()?;
        let result = self.repository.list_refs(pattern, &self.token, "sdk").await;
        self.identity()?;
        result.map_err(|error| repository_error(error, &self.trace))
    }

    pub(super) async fn history(&self, name: &str, from: u64) -> Result<RefHistory, ConnectError> {
        self.identity()?;
        let result = self
            .repository
            .ref_history(name, from, &self.token, "sdk")
            .await;
        self.identity()?;
        result.map_err(|error| repository_error(error, &self.trace))
    }
}

pub(super) fn protocol(outcome: Outcome, trace: &str) -> ConnectError {
    ProtocolError::from_outcome(outcome, trace).into()
}

fn repository_error(error: Error, trace: &str) -> ConnectError {
    let outcome = match error {
        Error::Denied | Error::Absent => Outcome::NotFound,
        Error::Store(error) => match error.kind() {
            StoreErrorKind::Denied { .. } | StoreErrorKind::Absent(_) => Outcome::NotFound,
            StoreErrorKind::Unsupported => Outcome::MethodUnavailable,
            StoreErrorKind::Unavailable { .. } => Outcome::Transient(None),
            // Names and patterns are checked before repository dispatch. A
            // malformed retained backend record is an internal failure.
            StoreErrorKind::Invalid(_) => Outcome::Internal,
            _ => Outcome::Internal,
        },
        _ => Outcome::Internal,
    };
    protocol(outcome, trace)
}
