//! Checked inventory and durable deletion through one already-owned SQL fence.
//!
//! Acquisition prepays one diagnostic bank. Successful operations return that
//! same bank to the fence; failures transfer it to the original typed error and
//! permanently consume checked reuse. No operation acquires another writer.

use crate::content_store::batch::{admission_under, allocation_under};

use rusqlite::types::ValueRef;

use super::*;
use crate::content_store::batch::{account, with_id_text};
use crate::owned_decode::{DecodeBudget, DecodeScratch};
use batch::{busy, diagnostic, metadata};

struct CheckedFence<'a> {
    inner: SqliteInventoryFence<'a>,
    account: DecodeBudget,
    diagnostic: Option<DecodeScratch>,
    _credit: DecodeScratch,
}

pub(super) fn acquire<'a>(
    backend: &'a SqliteBlobBackend,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<Box<dyn BlobInventoryFence + 'a>, StoreError> {
    Ok(Box::new(acquire_owned(backend, boundary)?))
}

fn acquire_owned<'a>(
    backend: &'a SqliteBlobBackend,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<CheckedFence<'a>, StoreError> {
    let account = account()?;
    catalog::write_available()?;
    check(backend, &account, boundary)?;
    let credit = account
        .reserve_scratch_array::<CheckedFence<'_>>(1)
        .map_err(|error| admission_under(&account, error))?;
    let diagnostic = diagnostic::admit(
        &account,
        backend.maximum_sqlite_heap_bytes,
        Some(&backend.root),
    )?;
    let result = (|| {
        let mut original = || check(backend, &account, boundary);
        let staging = catalog::write_gate_with_boundary(&mut original)?;
        let lock = backend.inventory_lock_with_boundary(&account, &mut original)?;
        let mut connection = backend.connection_with_boundary(&mut original)?;
        let accepted = busy::with_zero(
            &account,
            &mut connection,
            &backend.quarantined,
            &mut original,
            |connection, _, original| {
                metadata::load_with_boundary(connection, false, original, &backend.quarantined)
            },
        )?;
        let (instance, generation) = accepted.finish(|value| {
            original()?;
            Ok(value)
        })?;
        Ok(SqliteInventoryFence {
            backend,
            operation: None,
            _staging: Some(staging),
            connection,
            _lock: lock,
            instance,
            generation,
        })
    })();
    match result {
        Ok(inner) => Ok(CheckedFence {
            inner,
            account,
            diagnostic: Some(diagnostic),
            _credit: credit,
        }),
        Err(error) => diagnostic::retain_failure(diagnostic, || Err(error)),
    }
}

fn check(
    backend: &SqliteBlobBackend,
    account: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    account
        .verify_live()
        .map_err(|error| admission_under(account, error))?;
    busy::healthy(&backend.quarantined)?;
    boundary()?;
    account
        .verify_live()
        .map_err(|error| admission_under(account, error))?;
    busy::healthy(&backend.quarantined)
}

impl CheckedFence<'_> {
    fn run<T>(
        &mut self,
        work: impl FnOnce(&mut SqliteInventoryFence<'_>, &DecodeBudget) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let _scope = self.account.enter();
        if let Err(source) = self.account.verify_live() {
            return Err(self.retain_checked_failure(admission_under(&self.account, source)));
        }
        let diagnostic = self.diagnostic.take().ok_or(StoreError::Unsupported {
            capability: "consumed-checked-sqlite-inventory-fence",
        })?;
        match work(&mut self.inner, &self.account) {
            Ok(value) => {
                self.diagnostic = Some(diagnostic);
                Ok(value)
            }
            Err(error) => diagnostic::retain_failure(diagnostic, || Err(error)),
        }
    }
}

impl BlobInventoryFence for CheckedFence<'_> {
    fn retain_checked_failure(&mut self, error: StoreError) -> StoreError {
        let Some(credit) = self.diagnostic.take() else {
            return error;
        };
        diagnostic::retain_error(credit, error)
    }

    fn visit_inventory(
        &mut self,
        _visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        Err(StoreError::Unsupported {
            capability: "checked-inventory-fence-requires-boundary",
        })
    }

    fn delete_candidate(&mut self, _id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        Err(StoreError::Unsupported {
            capability: "checked-inventory-fence-requires-boundary",
        })
    }

    fn visit_inventory_with_boundary(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<InventorySummaryReceipt, StoreError> {
        self.run(|inner, account| {
            let backend = inner.backend;
            let mut original = || check(backend, account, boundary);
            original()?;
            let credit = account
                .reserve_scratch_bytes(backend.name.len() as u64)
                .map_err(|error| admission_under(account, error))?;
            let mut name = String::new();
            name.try_reserve_exact(backend.name.len())
                .map_err(|error| allocation_under(account, error))?;
            name.push_str(&backend.name);
            let accepted = busy::with_zero(
                account,
                &mut inner.connection,
                &backend.quarantined,
                &mut original,
                |connection, _, original| {
                    let observed = metadata::load_with_boundary(
                        connection,
                        false,
                        original,
                        &backend.quarantined,
                    )?;
                    if observed != (inner.instance, inner.generation) {
                        return Err(invalid_metadata());
                    }
                    let generation = persistent_inventory_generation(
                        &backend.name,
                        inner.instance,
                        inner.generation,
                    )?;
                    let mut inventory = InventoryCounter::new(
                        physical_storage_identity(inner.instance),
                        generation,
                    );
                    original()?;
                    let mut statement =
                        connection
                            .prepare(diagnostic::INVENTORY_SQL)
                            .map_err(|source| {
                                database_error("prepare-sqlite-blob-inventory", source)
                            })?;
                    original()?;
                    let mut rows = statement
                        .query([])
                        .map_err(|source| database_error("query-sqlite-blob-inventory", source))?;
                    loop {
                        original()?;
                        let row = rows.next().map_err(|source| {
                            database_error("visit-sqlite-blob-inventory", source)
                        })?;
                        original()?;
                        let Some(row) = row else {
                            break;
                        };
                        let id = inventory_id(row)?;
                        let length: i64 = row.get(1).map_err(|source| {
                            database_error("decode-sqlite-blob-length", source)
                        })?;
                        let logical_length =
                            u64::try_from(length).map_err(|_| StoreError::Corrupt { id })?;
                        let record = BlobInventoryRecord::new(id, logical_length);
                        original()?;
                        visitor(record)?;
                        original()?;
                        inventory.push(record)?;
                    }
                    drop(rows);
                    drop(statement);
                    original()?;
                    Ok(inventory.finish(name))
                },
            )?;
            let accepted = accepted.check(|_| original())?;
            Ok(InventorySummaryReceipt::new(accepted, credit))
        })
    }

    fn delete_candidates_with_boundary(
        &mut self,
        ids: &[ContentId],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<DeleteBatchReceipt, StoreError> {
        self.run(|inner, account| {
            let backend = inner.backend;
            let mut original = || check(backend, account, boundary);
            original()?;
            if ids.len() > MAX_BATCH_OBJECTS {
                return Err(StoreError::Quota);
            }
            let credit = account
                .reserve_scratch_array::<PlannedDeleteDisposition>(ids.len())
                .map_err(|error| admission_under(account, error))?;
            let mut dispositions = Vec::new();
            dispositions
                .try_reserve_exact(ids.len())
                .map_err(|error| allocation_under(account, error))?;
            let accepted = busy::with_zero(
                account,
                &mut inner.connection,
                &backend.quarantined,
                &mut original,
                |connection, progress, original| {
                    let shared: &Connection = connection;
                    let mut transaction =
                        busy::retry(shared, false, &backend.quarantined, original, |_| {
                            rusqlite::Transaction::new_unchecked(
                                shared,
                                rusqlite::TransactionBehavior::Deferred,
                            )
                            .map_err(|source| database_error("begin-sqlite-blob-delete", source))
                        })?;
                    transaction.set_drop_behavior(rusqlite::DropBehavior::Ignore);
                    progress.began();
                    let observed = metadata::load_with_boundary(
                        &transaction,
                        true,
                        original,
                        &backend.quarantined,
                    )?;
                    if observed != (inner.instance, inner.generation) {
                        return Err(invalid_metadata());
                    }
                    let mut planned = 0_u64;
                    for (index, id) in ids.iter().enumerate() {
                        original()?;
                        if ids[..index].contains(id) {
                            continue;
                        }
                        let present: bool = busy::retry(
                            &transaction,
                            true,
                            &backend.quarantined,
                            original,
                            |_| {
                                with_id_text(*id, |encoded| {
                                    transaction
                                        .query_row(diagnostic::PRESENCE_SQL, [encoded], |row| {
                                            row.get(0)
                                        })
                                        .map_err(|source| {
                                            database_error("test-sqlite-delete-presence", source)
                                        })
                                })
                            },
                        )?;
                        planned += u64::from(present);
                    }
                    // Preflight every actual removal before the first DELETE,
                    // including SQLite's signed generation representation.
                    let next = inner
                        .generation
                        .checked_add(planned)
                        .ok_or(StoreError::Quota)?;
                    i64::try_from(next).map_err(|_| StoreError::Quota)?;
                    let mut removed_total = 0_u64;
                    for id in ids {
                        original()?;
                        let removed = busy::retry(
                            &transaction,
                            true,
                            &backend.quarantined,
                            original,
                            |_| {
                                with_id_text(*id, |encoded| {
                                    transaction
                                        .execute(diagnostic::DELETE_SQL, [encoded])
                                        .map_err(|source| {
                                            database_error("delete-sqlite-blob-candidate", source)
                                        })
                                })
                            },
                        )?;
                        let disposition = match removed {
                            0 => PlannedDeleteDisposition::AlreadyAbsent,
                            1 => {
                                metadata::advance_with_boundary(
                                    &transaction,
                                    original,
                                    &backend.quarantined,
                                )?;
                                removed_total += 1;
                                PlannedDeleteDisposition::Deleted
                            }
                            _ => return Err(invalid_metadata()),
                        };
                        dispositions.push(disposition);
                        original()?;
                    }
                    if removed_total != planned {
                        return Err(invalid_metadata());
                    }
                    let commit =
                        busy::retry(&transaction, true, &backend.quarantined, original, |_| {
                            transaction.execute_batch("COMMIT").map_err(|source| {
                                database_error("commit-sqlite-blob-delete", source)
                            })
                        });
                    if let Err(error) = commit {
                        progress.commit_failed(&transaction);
                        return Err(error);
                    }
                    progress.committed();
                    // A later callback cannot turn this durable mutation into
                    // rollback or leave the held fence's generation stale.
                    inner.generation = next;
                    if !transaction.is_autocommit() {
                        backend
                            .quarantined
                            .store(true, std::sync::atomic::Ordering::Release);
                        return Err(StoreError::Unavailable);
                    }
                    drop(transaction);
                    original()?;
                    Ok(dispositions)
                },
            )?;
            let accepted = accepted.check(|_| original())?;
            Ok(DeleteBatchReceipt::new(accepted, credit))
        })
    }
}

fn inventory_id(row: &rusqlite::Row<'_>) -> Result<ContentId, StoreError> {
    let value = row
        .get_ref(0)
        .map_err(|source| database_error("decode-sqlite-blob-id", source))?;
    match value {
        ValueRef::Text(bytes) => {
            let text = std::str::from_utf8(bytes).map_err(|_| StoreError::InvalidId)?;
            ContentId::parse(text)
        }
        other => Err(database_error(
            "decode-sqlite-blob-id",
            rusqlite::Error::InvalidColumnType(0, "id".to_owned(), other.data_type()),
        )),
    }
}

#[cfg(test)]
mod tests;
