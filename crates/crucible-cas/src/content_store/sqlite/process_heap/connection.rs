//! Publishes managed native connections before opening and retains failed closes.

use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

use rusqlite::{Connection, OpenFlags};

use super::{HeapFailure, Phase, SqliteProcessHeap, close_connection, process, refusal};
use crate::content_store::StoreError;
use crate::owned_decode::ResourceLoan;

pub(super) struct ConnectionOwner {
    connection: Mutex<Option<Connection>>,
    // Original credit remains live until the Arc allocation has closed.
    _metadata: ResourceLoan,
}

impl ConnectionOwner {
    pub(super) fn close(&self) -> Result<(), HeapFailure> {
        let mut slot = self
            .connection
            .lock()
            .map_err(|_| HeapFailure::PoisonedConnection)?;
        if let Some(connection) = slot.take()
            && let Err((connection, error)) = connection.close()
        {
            *slot = Some(connection);
            return Err(error.into());
        }
        Ok(())
    }
}

/// Retains a managed connection in the same original process heap.
///
/// No owned native connection or raw handle escapes. Every database operation
/// verifies its heap before taking this connection's individual lock.
pub struct SqliteConnection {
    connection: Option<Arc<ConnectionOwner>>,
    heap: SqliteProcessHeap,
}

impl Clone for SqliteConnection {
    fn clone(&self) -> Self {
        Self {
            connection: self.connection.clone(),
            heap: self.heap.clone(),
        }
    }
}

impl SqliteProcessHeap {
    /// Opens a connection after publishing its exact retained metadata owner.
    ///
    /// # Errors
    /// Refuses closed original authority, exhausted connection slots, unpaid
    /// metadata, native open failure or an uncertain constructor unwind.
    pub fn open_connection(
        &self,
        path: impl AsRef<Path>,
        flags: OpenFlags,
    ) -> Result<SqliteConnection, StoreError> {
        self.open_connection_for(path, flags, "open-managed-sqlite-connection")
    }

    pub(in crate::content_store::sqlite) fn open_connection_for(
        &self,
        path: impl AsRef<Path>,
        flags: OpenFlags,
        operation: &'static str,
    ) -> Result<SqliteConnection, StoreError> {
        self.verify_live()?;
        let owner = self.identity()?;
        let metadata = owner.issuer.authority()?.reserve_metadata(
            (std::mem::size_of::<ConnectionOwner>() + 2 * std::mem::size_of::<usize>()) as u64,
        )?;
        self.verify_live()?;
        let handle = SqliteConnection {
            connection: Some(Arc::new(ConnectionOwner {
                connection: Mutex::new(None),
                _metadata: metadata,
            })),
            heap: self.clone(),
        };
        // No raw owning Arc survives this handle. Every unpublished refusal
        // extracts the body only after closing its selected control.
        let connection = handle
            .connection
            .as_ref()
            .ok_or_else(|| refusal("SQLite connection control is absent"))?;
        {
            let mut state = process()?;
            let installed = state
                .installed
                .as_mut()
                .filter(|installed| Arc::ptr_eq(&installed.owner, owner))
                .ok_or_else(|| refusal("SQLite connection names a stale scope"))?;
            if installed.phase != Phase::Active {
                return Err(installed
                    .error("SQLite connection admission has closed")
                    .into());
            }
            let slot = installed
                .connections
                .iter_mut()
                .find(|slot| slot.is_none())
                .ok_or_else(|| refusal("SQLite connection roster is exhausted"))?;
            *slot = Some(connection.clone());
        }
        // An unwinding native constructor retains the published process owner.
        // The pinned ordinary error path closes its unexposed failed DB handle;
        // that source assumption is separately covered by first-entry controls.
        let opened = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Connection::open_with_flags(path, flags)
        }));
        match opened {
            Ok(Ok(native)) => {
                // This fresh mutex is inaccessible before publication. No
                // operation guard can poison it before this first native move.
                let mut slot = connection
                    .connection
                    .lock()
                    .map_err(|_| refusal("SQLite connection publication is poisoned"))?;
                *slot = Some(native);
                drop(slot);
                Ok(handle)
            }
            Ok(Err(source)) => Err(super::super::database_error(operation, source)),
            Err(panic) => {
                if let Ok(mut state) = process()
                    && let Some(installed) = state.installed.as_mut()
                {
                    installed.phase = Phase::Quarantined;
                }
                std::panic::resume_unwind(panic)
            }
        }
    }
}

/// Borrows one native operation without allowing the connection to escape.
pub(in crate::content_store::sqlite) struct SqliteConnectionGuard<'a> {
    guard: MutexGuard<'a, Option<Connection>>,
}

impl Deref for SqliteConnectionGuard<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        // The constructor returns this guard only after validating Some. Its
        // exclusive lock prevents terminal close for the guard's entire life.
        match self.guard.as_ref() {
            Some(connection) => connection,
            None => unreachable!("validated managed connection"),
        }
    }
}

impl DerefMut for SqliteConnectionGuard<'_> {
    fn deref_mut(&mut self) -> &mut Connection {
        match self.guard.as_mut() {
            Some(connection) => connection,
            None => unreachable!("validated managed connection"),
        }
    }
}

impl SqliteConnection {
    pub(in crate::content_store::sqlite) fn lock(
        &self,
    ) -> Result<SqliteConnectionGuard<'_>, StoreError> {
        self.lock_for("lock-managed-sqlite-connection")
    }

    pub(in crate::content_store::sqlite) fn lock_for(
        &self,
        operation: &'static str,
    ) -> Result<SqliteConnectionGuard<'_>, StoreError> {
        self.heap.verify_live()?;
        let owner = self
            .connection
            .as_ref()
            .ok_or_else(|| refusal("SQLite connection handle has closed"))?;
        let guard = owner
            .connection
            .lock()
            .map_err(|_| StoreError::Poisoned { operation })?;
        self.heap.verify_live()?;
        if guard.is_none() {
            return Err(refusal("SQLite native connection has closed").into());
        }
        Ok(SqliteConnectionGuard { guard })
    }

    pub(in crate::content_store::sqlite) fn try_lock_for(
        &self,
        operation: &'static str,
    ) -> Result<Option<SqliteConnectionGuard<'_>>, StoreError> {
        self.heap.verify_live()?;
        let owner = self
            .connection
            .as_ref()
            .ok_or_else(|| refusal("SQLite connection handle has closed"))?;
        match owner.connection.try_lock() {
            Ok(guard) => {
                self.heap.verify_live()?;
                if guard.is_none() {
                    return Err(refusal("SQLite native connection has closed").into());
                }
                Ok(Some(SqliteConnectionGuard { guard }))
            }
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Poisoned(_)) => Err(StoreError::Poisoned { operation }),
        }
    }

    /// Executes SQL while retaining this connection and the original heap.
    ///
    /// # Errors
    /// Refuses closed ownership, native SQL errors or poisoned connection state.
    pub fn execute<P: rusqlite::Params>(&self, sql: &str, params: P) -> Result<usize, StoreError> {
        self.lock()?
            .execute(sql, params)
            .map_err(|source| super::super::database_error("execute-managed-sqlite", source))
    }

    /// Executes a sequence under the same managed native connection lock.
    ///
    /// # Errors
    /// Refuses closed ownership, native SQL errors or poisoned connection state.
    pub fn execute_batch(&self, sql: &str) -> Result<(), StoreError> {
        self.lock()?
            .execute_batch(sql)
            .map_err(|source| super::super::database_error("execute-managed-sqlite-batch", source))
    }

    /// Reads one row without releasing the original heap during conversion.
    ///
    /// # Errors
    /// Refuses closed ownership, query/conversion errors or poisoned state.
    pub fn query_row<T, P, F>(&self, sql: &str, params: P, row: F) -> Result<T, StoreError>
    where
        P: rusqlite::Params,
        F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    {
        self.lock()?
            .query_row(sql, params, row)
            .map_err(|source| super::super::database_error("query-managed-sqlite", source))
    }
}

impl Drop for SqliteConnection {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            drop(Arc::into_inner(connection));
        }
        if let Ok(mut state) = process()
            && let Some(installed) = state.installed.as_mut()
            && self
                .heap
                .identity()
                .is_ok_and(|owner| Arc::ptr_eq(owner, &installed.owner))
            && installed.phase != Phase::Quarantined
        {
            for index in 0..installed.connections.len() {
                let idle = installed.connections[index]
                    .as_ref()
                    .is_some_and(|owner| Arc::strong_count(owner) == 1);
                if !idle {
                    continue;
                }
                let Some(owner) = installed.connections[index].as_ref() else {
                    continue;
                };
                let previous_phase = installed.phase;
                installed.phase = Phase::Quarantined;
                if let Err(mut error) = close_connection(installed, owner) {
                    if let Some(owner) = error.owner.take() {
                        drop(Arc::into_inner(owner));
                    }
                    break;
                }
                installed.phase = previous_phase;
                if let Some(owner) = installed.connections[index].take() {
                    drop(Arc::into_inner(owner));
                }
            }
        }
        // The heap field closes last. Its terminal attempt sees no connection
        // alias from this handle, including the actual last deferred reader.
    }
}
