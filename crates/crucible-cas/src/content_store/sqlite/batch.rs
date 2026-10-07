//! Bounded SQLite batch publication under the existing caller operation.

use std::sync::TryLockError;

use super::*;
use crate::content_store::batch::{
    account, admission, admit_receipts, allocation, read_source, with_id_text,
};

pub(super) mod busy;
pub(super) mod diagnostic;
pub(super) mod metadata;
mod reader;

impl SqliteBlobBackend {
    pub(super) fn put_batch_with_boundary(
        &self,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PutBatchReceipt, StoreError> {
        busy::healthy(&self.quarantined)?;
        boundary()?;
        let account = account()?;
        if objects.len() > MAX_BATCH_OBJECTS {
            return Err(StoreError::Quota);
        }
        let operation = self
            .catalog_supervisor
            .as_ref()
            .map(|supervisor| supervisor.begin(SqliteCatalogOperationKind::Write))
            .transpose()?;
        let _staging = catalog::write_gate_with_boundary(&mut || {
            check_original(boundary, &account, operation.as_deref())
        })?;

        // Sources may read this same database. Authenticate every source
        // before taking the inventory or write-connection lock.
        let _staged_credit = account
            .reserve_scratch_array::<(ContentId, OwnedBlobBytes)>(objects.len())
            .map_err(admission)?;
        let receipt_credit = admit_receipts(&account, objects.len(), self.name.len())?;
        let staged = {
            let mut check = || check_original(boundary, &account, operation.as_deref());
            let mut staged = Vec::new();
            staged
                .try_reserve_exact(objects.len())
                .map_err(allocation)?;
            let mut total_bytes = 0_u64;
            for (id, source) in objects {
                check()?;
                total_bytes = total_bytes
                    .checked_add(source.logical_length())
                    .ok_or(StoreError::Quota)?;
                if total_bytes > MAX_BATCH_BYTES {
                    return Err(StoreError::Quota);
                }
                let bytes =
                    read_source(source, MAX_BATCH_BYTES, &mut check).map_err(
                        |error| match error {
                            StoreError::InvalidSourceLength { .. } => {
                                StoreError::Corrupt { id: *id }
                            }
                            other => other,
                        },
                    )?;
                validate_bytes(*id, &bytes)?;
                check()?;
                staged.push((*id, bytes));
            }
            staged
        };

        let diagnostic_credit =
            diagnostic::admit(self.maximum_sqlite_heap_bytes, Some(&self.root))?;
        diagnostic::retain_failure(diagnostic_credit, || {
            let _inventory_lock = self.inventory_lock_with_boundary(&mut || {
                check_original(boundary, &account, operation.as_deref())
            })?;
            let mut connection = self.connection_with_boundary(&mut || {
                check_original(boundary, &account, operation.as_deref())
            })?;
            let accepted = busy::with_zero(
                &mut connection,
                &self.quarantined,
                &mut || check_original(boundary, &account, operation.as_deref()),
                |connection, progress, check| {
                    let shared: &Connection = connection;
                    let mut transaction =
                        busy::retry(shared, false, &self.quarantined, check, |_| {
                            rusqlite::Transaction::new_unchecked(
                                shared,
                                rusqlite::TransactionBehavior::Deferred,
                            )
                            .map_err(|source| database_error("begin-sqlite-blob-batch", source))
                        })?;
                    transaction.set_drop_behavior(rusqlite::DropBehavior::Ignore);
                    progress.began();
                    check()?;
                    let mut inserted = false;
                    for (id, bytes) in &staged {
                        check()?;
                        let exists: bool =
                            busy::retry(&transaction, true, &self.quarantined, check, |_| {
                                with_id_text(*id, |encoded| {
                                    transaction
                                        .query_row(diagnostic::PRESENCE_SQL, [encoded], |row| {
                                            row.get(0)
                                        })
                                        .map_err(|source| {
                                            database_error("test-sqlite-batch-presence", source)
                                        })
                                })
                            })?;
                        check()?;
                        if exists {
                            authenticate_stored_with_boundary(
                                &transaction,
                                *id,
                                check,
                                Some(&account),
                                Some(&self.quarantined),
                            )?;
                        } else {
                            busy::retry(&transaction, true, &self.quarantined, check, |_| {
                                with_id_text(*id, |encoded| {
                                    transaction
                                        .execute(
                                            diagnostic::INSERT_SQL,
                                            params![encoded, &bytes[..]],
                                        )
                                        .map_err(|source| {
                                            database_error("stage-sqlite-batch-object", source)
                                        })
                                })
                            })?;
                            inserted = true;
                        }
                        check()?;
                    }
                    if inserted {
                        check()?;
                        metadata::advance_with_boundary(&transaction, check, &self.quarantined)?;
                    }
                    let commit = busy::retry(&transaction, true, &self.quarantined, check, |_| {
                        transaction
                            .execute_batch("COMMIT")
                            .map_err(|source| database_error("commit-sqlite-blob-batch", source))
                    });
                    if let Err(error) = commit {
                        progress.commit_failed(&transaction);
                        return Err(error);
                    }
                    progress.committed();
                    if !transaction.is_autocommit() {
                        self.quarantined
                            .store(true, std::sync::atomic::Ordering::Release);
                        return Err(StoreError::Unavailable);
                    }
                    check()?;
                    drop(transaction);
                    Ok(())
                },
            )?;

            accepted.finish(|()| {
                let mut check = || check_original(boundary, &account, operation.as_deref());
                let mut receipts = Vec::new();
                receipts
                    .try_reserve_exact(staged.len())
                    .map_err(allocation)?;
                for (id, bytes) in &staged {
                    check()?;
                    receipts.push(sqlite_receipt(&self.name, *id, bytes.len() as u64));
                }
                check()?;
                if let Some(operation) = operation {
                    operation.complete()?;
                }
                boundary()?;
                account.verify_live().map_err(admission)?;
                busy::healthy(&self.quarantined)?;
                Ok(PutBatchReceipt::new(receipts, receipt_credit))
            })
        })
    }

    pub(super) fn connection_with_boundary(
        &self,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<MutexGuard<'_, Connection>, StoreError> {
        loop {
            busy::healthy(&self.quarantined)?;
            boundary()?;
            match self.connection.try_lock() {
                Ok(connection) => {
                    busy::healthy(&self.quarantined)?;
                    boundary()?;
                    return Ok(connection);
                }
                Err(TryLockError::WouldBlock) => std::thread::yield_now(),
                Err(TryLockError::Poisoned(_)) => {
                    return Err(StoreError::Poisoned {
                        operation: "lock-sqlite-blob-connection",
                    });
                }
            }
        }
    }

    pub(super) fn inventory_lock_with_boundary(
        &self,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<File, StoreError> {
        boundary()?;
        let path = diagnostic::lock_path(&self.root)?;
        let file = open_inventory_lock(&path, false)?;
        busy::healthy(&self.quarantined)?;
        loop {
            busy::healthy(&self.quarantined)?;
            boundary()?;
            match flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => {
                    busy::healthy(&self.quarantined)?;
                    boundary()?;
                    return Ok(file);
                }
                Err(source)
                    if source == rustix::io::Errno::WOULDBLOCK
                        || source == rustix::io::Errno::INTR =>
                {
                    std::thread::yield_now()
                }
                Err(source) => {
                    return Err(StoreError::Io {
                        operation: "lock-sqlite-inventory",
                        path,
                        source: io::Error::from_raw_os_error(source.raw_os_error()),
                    });
                }
            }
        }
    }
}

fn check_original(
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    account: &crate::owned_decode::DecodeBudget,
    operation: Option<&dyn SqliteCatalogOperation>,
) -> Result<(), StoreError> {
    boundary()?;
    account.verify_live().map_err(admission)?;
    if let Some(operation) = operation {
        operation.check()?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod tests;
