//! Retains two fixed SQL statements through one bounded checked transaction.
//!
//! Every row still checks current presence and authenticates an existing body.
//! Statement reuse changes preparation frequency, not transaction or batch bounds.

use std::sync::atomic::AtomicBool;

use super::*;
use crate::owned_decode::DecodeScratch;
use rusqlite::Statement;

struct BatchStatements<'connection> {
    presence: Statement<'connection>,
    insert: Option<Statement<'connection>>,
    #[cfg(test)]
    _closed: StatementsClosed,
    // Fields close in declaration order: both native handles precede this loan.
    _credit: DecodeScratch,
}

impl<'connection> BatchStatements<'connection> {
    fn prepare(
        connection: &'connection Connection,
        original: &crate::owned_decode::DecodeBudget,
        quarantined: &AtomicBool,
        check: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        // Cover the fixed owner and transient move/prepare headers before the
        // first handle. Native allocations use the connection's already-paid
        // managed process heap. The caller's diagnostic loan separately covers
        // converted errors; this loan covers the new fixed Rust headers.
        let bytes = control_bytes()?;
        let credit = original
            .reserve_scratch_bytes(bytes)
            .map_err(|error| admission_under(original, error))?;
        let presence = prepare_statement(
            connection,
            diagnostic::PRESENCE_SQL,
            "test-sqlite-batch-presence",
            quarantined,
            check,
        )?;
        Ok(Self {
            presence,
            insert: None,
            #[cfg(test)]
            _closed: StatementsClosed,
            _credit: credit,
        })
    }

    fn contains(
        &mut self,
        connection: &Connection,
        id: ContentId,
        quarantined: &AtomicBool,
        check: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<bool, StoreError> {
        busy::retry(connection, true, quarantined, check, |_| {
            with_id_text(id, |encoded| {
                let result = self.presence.query_row([encoded], |row| row.get(0));
                // The API has reset its cursor. Free copied bindings before the
                // next row, duplicate authentication or a BUSY retry.
                self.presence.clear_bindings();
                result.map_err(|source| database_error("test-sqlite-batch-presence", source))
            })
        })
    }

    fn insert(
        &mut self,
        connection: &'connection Connection,
        id: ContentId,
        bytes: &[u8],
        quarantined: &AtomicBool,
        check: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        // An all-existing batch never prepares an INSERT. Its first absent row
        // admits the one fixed handle; later rows reuse it after execute resets.
        if self.insert.is_none() {
            self.insert = Some(prepare_statement(
                connection,
                diagnostic::INSERT_SQL,
                "stage-sqlite-batch-object",
                quarantined,
                check,
            )?);
        }
        let statement = self.insert.as_mut().ok_or(StoreError::Unavailable)?;
        busy::retry(connection, true, quarantined, check, |_| {
            with_id_text(id, |encoded| {
                let result = statement.execute(params![encoded, bytes]);
                // Retain only the prepared program, not a previous row's copied
                // body. The original result remains owned across this cleanup.
                statement.clear_bindings();
                let rows =
                    result.map_err(|source| database_error("stage-sqlite-batch-object", source))?;
                #[cfg(test)]
                PREPARES.with(|counts| {
                    let mut value = counts.get();
                    value[2] = value[2].saturating_add(rows);
                    counts.set(value);
                });
                Ok(rows)
            })
        })?;
        Ok(())
    }
}

pub(super) fn control_bytes() -> Result<u64, StoreError> {
    std::mem::size_of::<BatchStatements<'_>>()
        .checked_add(
            std::mem::size_of::<Statement<'_>>()
                .checked_mul(2)
                .ok_or(StoreError::Quota)?,
        )
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(StoreError::Quota)
}

fn prepare_statement<'connection>(
    connection: &'connection Connection,
    sql: &'static str,
    operation: &'static str,
    quarantined: &AtomicBool,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<Statement<'connection>, StoreError> {
    busy::retry(connection, true, quarantined, check, |_| {
        #[cfg(test)]
        PREPARES.with(|counts| {
            let mut value = counts.get();
            let slot = usize::from(sql == diagnostic::INSERT_SQL);
            value[slot] = value[slot].saturating_add(1);
            counts.set(value);
        });
        connection
            .prepare(sql)
            .map_err(|source| database_error(operation, source))
    })
}

pub(super) fn stage(
    connection: &Connection,
    objects: &[(ContentId, OwnedBlobBytes)],
    original: &crate::owned_decode::DecodeBudget,
    quarantined: &AtomicBool,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<bool, StoreError> {
    if objects.is_empty() {
        return Ok(false);
    }
    let mut statements = BatchStatements::prepare(connection, original, quarantined, check)?;
    let mut inserted = false;
    for (id, bytes) in objects {
        check()?;
        let exists = statements.contains(connection, *id, quarantined, check)?;
        check()?;
        if exists {
            authenticate_stored_with_boundary(
                connection,
                *id,
                check,
                Some(original),
                Some(quarantined),
            )?;
        } else {
            statements.insert(connection, *id, bytes, quarantined, check)?;
            inserted = true;
        }
        check()?;
    }
    // Statement query/execute has reset every cursor. Safe binding Drop then
    // finalizes both handles before metadata, COMMIT or the caller's cleanup.
    // Its ignored finalize-status behavior is inherited from query_row/execute.
    drop(statements);
    Ok(inserted)
}

#[cfg(test)]
std::thread_local! {
    // Inline test observer counts actual prepare attempts on this test thread.
    // It neither issues authority nor participates in production allocation.
    static WATCH_CREDIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static PREPARES: std::cell::Cell<[usize; 4]> = const { std::cell::Cell::new([0; 4]) };
}

#[cfg(test)]
pub(super) fn reset_preparations() {
    WATCH_CREDIT.with(|enabled| enabled.set(true));
    PREPARES.with(|counts| counts.set([0; 4]));
}

#[cfg(test)]
pub(super) fn preparations() -> [usize; 4] {
    PREPARES.with(std::cell::Cell::get)
}

// The zero-sized witness runs after both native Statement fields have dropped,
// before the original control credit. It observes real field-drop ordering;
// reset/finalize return statuses remain unobserved in the pinned safe binding.
#[cfg(test)]
struct StatementsClosed;

#[cfg(test)]
impl Drop for StatementsClosed {
    fn drop(&mut self) {
        PREPARES.with(|counts| {
            let mut value = counts.get();
            value[3] = value[3].saturating_add(1);
            counts.set(value);
        });
    }
}

#[cfg(test)]
pub(super) fn assert_handles_closed_before_credit() {
    if !WATCH_CREDIT.with(std::cell::Cell::get) {
        return;
    }
    assert!(
        preparations()[3] > 0,
        "the actual statement fields must close before their original credit"
    );
}
