//! Private bounded SQLite retry journal for exact direct-upload control waves.
//!
//! A direct object journal belongs to an authenticated deployment/principal scope.
//! A separate metadata-admission journal binds original Hub/registry/inventory
//! selectors before the publication exists; it grants no provider authority.
//! It contains immutable logical descriptors and receipts, never bearer URLs,
//! provider UploadIds or file bodies. Each dispatched wave is committed with
//! SQLite synchronous EXTRA before the caller receives its reservation.
//!
//! The existing parent must be owner-private (0700), and the file owner-private
//! (0600), singly linked and ordinary. SQLite uses an absolute pathname after
//! descriptor checks; trusted same-owner custody remains necessary between
//! those checks and VFS access. A valid private hot rollback journal may recover
//! on open. This is client retry custody, not provider-effect authority.

mod filesystem;
mod operations;
mod publication;
pub use publication::{DirectPublicationAdmission, DirectPublicationHeader};
mod sqlite;

use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};

use super::DirectClientError;
use filesystem::PrivateFile;

pub use filesystem::ensure_private_checkpoint_directory;

struct State {
    file: PrivateFile,
    connection: Mutex<Connection>,
    budget: Arc<tokio::sync::Semaphore>,
    run_id: String,
}

/// Retains direct-upload retries in one private, bounded SQLite journal.
#[derive(Clone)]
pub struct SqliteDirectCheckpoints {
    state: Arc<State>,
}

impl fmt::Debug for SqliteDirectCheckpoints {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SqliteDirectCheckpoints([private journal])")
    }
}

impl SqliteDirectCheckpoints {
    /// Creates or opens an explicitly selected authenticated-scope journal.
    ///
    /// `namespace` is a lowercase SHA-256 commitment supplied by the adapter
    /// over authenticated Hub/deployment/principal identity. It is not inferred
    /// from a bearer token. `create` is exclusive; opening never initializes,
    /// migrates, changes journal mode or adopts a different existing database.
    /// The caller retains the journal on failure for explicit reconciliation.
    ///
    /// # Errors
    /// Refuses non-private custody, changed identity/schema, unsupported WAL,
    /// malformed namespace or durable initialization failure.
    pub async fn open(
        path: &Path,
        namespace: &str,
        create: bool,
    ) -> Result<Self, DirectClientError> {
        if namespace.len() != 64
            || !namespace
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DirectClientError::Checkpoint);
        }
        let path = path.to_owned();
        let namespace = namespace.to_owned();
        tokio::task::spawn_blocking(move || {
            let file = PrivateFile::admit(&path, create)?;
            let mut connection = Connection::open_with_flags(
                file.path(),
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|_| DirectClientError::Checkpoint)?;
            sqlite::limits(&connection)?;
            file.verify()?;
            let run_id = if create {
                let run_id = hex::encode(rand::random::<[u8; 32]>());
                sqlite::configure(&connection)?;
                sqlite::initialize(&mut connection, &namespace, &run_id)?;
                file.sync_creation()?;
                run_id
            } else {
                // Identity admission precedes any configuration PRAGMA write.
                let run_id = sqlite::validate(&connection, &namespace)?;
                let mode: String = connection
                    .pragma_query_value(None, "journal_mode", |row| row.get(0))
                    .map_err(|_| DirectClientError::Checkpoint)?;
                if mode != "delete" {
                    return Err(DirectClientError::Checkpoint);
                }
                sqlite::configure(&connection)?;
                run_id
            };
            file.verify()?;
            Ok(Self {
                state: Arc::new(State {
                    file,
                    connection: Mutex::new(connection),
                    budget: Arc::new(tokio::sync::Semaphore::new(1)),
                    run_id,
                }),
            })
        })
        .await
        .map_err(|_| DirectClientError::Checkpoint)?
    }

    /// Returns the fresh run identity durably retained before any capability.
    ///
    /// Adapters include it in cache workflow operation commitments, so exact
    /// restart replays the same run while a deliberately new journal represents
    /// a new operation. It never erases earlier provider-control fences.
    pub fn run_id(&self) -> &str {
        &self.state.run_id
    }

    async fn reserve(&self) -> Result<tokio::sync::OwnedSemaphorePermit, DirectClientError> {
        self.state
            .budget
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| DirectClientError::Checkpoint)
    }

    async fn wave<T: Send + 'static>(
        &self,
        reservation: tokio::sync::OwnedSemaphorePermit,
        work: impl FnOnce(&Transaction<'_>) -> Result<T, DirectClientError> + Send + 'static,
    ) -> Result<T, DirectClientError> {
        let state = self.state.clone();
        tokio::task::spawn_blocking(move || {
            let _reservation = reservation;
            state.file.verify()?;
            let mut connection = state
                .connection
                .lock()
                .map_err(|_| DirectClientError::Checkpoint)?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| DirectClientError::Checkpoint)?;
            let result = work(&transaction)?;
            state.file.verify()?;
            transaction
                .commit()
                .map_err(|_| DirectClientError::Checkpoint)?;
            state.file.verify()?;
            Ok(result)
        })
        .await
        .map_err(|_| DirectClientError::Checkpoint)?
    }
}

#[cfg(test)]
mod tests;

/// One bounded page of original completion commitments from this private run.
#[derive(Debug)]
pub struct DirectCompletionPage {
    /// Exact original requests; no provider UploadIds, URLs or file bodies.
    pub items: Vec<DirectRetainedCompletion>,
    /// Exclusive lexical continuation, absent only at this retained end.
    pub next_after: Option<String>,
}

impl SqliteDirectCheckpoints {
    /// Reads original completions for a post-staging visibility barrier pass.
    ///
    /// The exclusive journal lock prevents another process changing the run.
    /// The adapter finishes staging before this pass and stops adding sessions
    /// while paginating. Returned commitments authorize no new provider effect:
    /// the server must replay their original operation and current ACL checks.
    ///
    /// # Errors
    /// Refuses invalid cursors, excessive limits, corrupted commitment custody,
    /// file replacement, schema or SQLite failures.
    pub async fn completion_page(
        &self,
        after: Option<&str>,
        maximum: usize,
    ) -> Result<DirectCompletionPage, DirectClientError> {
        use aos_proto_types::direct_upload::*;
        if maximum == 0
            || maximum > MAX_DIRECT_BATCH_ITEMS
            || after.is_some_and(|value| !valid_direct_identity(value))
        {
            return Err(DirectClientError::Checkpoint);
        }
        let reservation = self.reserve().await?;
        let after = after.unwrap_or("").to_owned();
        self.wave(reservation, move |transaction| {
            if !after.is_empty() {
                let known: bool = transaction.query_row(
                    "SELECT EXISTS(SELECT 1 FROM direct_records WHERE kind='complete' AND owner=?1)",
                    [&after], |row| row.get(0),
                ).map_err(|_| DirectClientError::Checkpoint)?;
                if !known {
                    return Err(DirectClientError::Checkpoint);
                }
            }
            let mut statement = transaction.prepare("SELECT owner,body FROM direct_records WHERE kind='complete' AND owner>?1 ORDER BY owner LIMIT ?2").map_err(|_| DirectClientError::Checkpoint)?;
            let mut rows = statement.query(rusqlite::params![after,maximum + 1]).map_err(|_| DirectClientError::Checkpoint)?;
            let mut items = Vec::with_capacity(maximum);
            let mut bytes = 0usize;
            let mut last = None;
            let mut more = false;
            while let Some(row) = rows.next().map_err(|_| DirectClientError::Checkpoint)? {
                let owner: String = row.get(0).map_err(|_| DirectClientError::Checkpoint)?;
                let length = row.get_ref(1).map_err(|_| DirectClientError::Checkpoint)?.as_blob().map_err(|_| DirectClientError::Checkpoint)?.len();
                if items.len() == maximum || bytes.checked_add(length).is_none_or(|total| total > MAX_DIRECT_CONTROL_BYTES - 256) {
                    more = true;
                    break;
                }
                let request: DirectCompleteRequest = sqlite::read(transaction, "complete", &owner, 0, 0)?.ok_or(DirectClientError::Checkpoint)?;
                if request.session.session_id != owner { return Err(DirectClientError::Checkpoint); }
                let validated = operations::complete(transaction, &request)?;
                bytes += length;
                last = Some(owner);
                let intent = operations::original_intent(transaction, &validated.session)?;
                items.push(DirectRetainedCompletion { request: validated, intent });
            }
            if more && items.is_empty() { return Err(DirectClientError::Checkpoint); }
            Ok(DirectCompletionPage { items, next_after: if more { last } else { None } })
        }).await
    }
}

/// Retains one completion plus its original source declaration for reply checks.
#[derive(Debug)]
pub struct DirectRetainedCompletion {
    /// Exact originally dispatched compact control commitment and CAS version.
    pub request: aos_proto_types::direct_upload::DirectCompleteRequest,
    /// Exact immutable source/owner declaration originally admitted to this run.
    pub intent: aos_proto_types::direct_upload::DirectUploadIntent,
}

mod oci;
pub use oci::DirectOciAllocation;
