//! Paused read snapshots retaining one original operation's unused error credit.
//!
//! Statements close after each private canonical record. A record's pending
//! EOF shares only the next metadata query's immediate supervision edge;
//! pauses close native state and locks before any caller invokes a visitor.

use super::super::process_heap::SqliteConnectionGuard;
use super::*;
use batch::busy::snapshot::SnapshotScope;

// Declaration order quarantines an unwound scope before either lock closes.
struct ActiveSnapshot<'backend> {
    scope: SnapshotScope<'backend>,
    connection: SqliteConnectionGuard<'backend>,
    staging: std::sync::MutexGuard<'static, ()>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Dormant,
    Active,
    Failed,
    Closed,
}

pub(crate) struct SqliteRamReadSession<'backend, 'original> {
    backend: &'backend SqliteBlobBackend,
    original: &'original DecodeBudget,
    active: Option<ActiveSnapshot<'backend>>,
    phase: Phase,
    pending_eof: bool,
    eof_refused: bool,
    diagnostic: Option<crate::owned_decode::DecodeScratch>,
    scope_credit: Option<crate::owned_decode::DecodeScratch>,
}

impl<'backend, 'original> SqliteRamReadSession<'backend, 'original> {
    pub(crate) fn new(
        backend: &'backend SqliteBlobBackend,
        original: &'original DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        original
            .verify_live()
            .map_err(|error| crate::content_store::batch::admission_under(original, error))?;
        crate::content_store::checked_reader::check(original, boundary)?;
        busy::healthy(&backend.quarantined)?;
        let diagnostic = diagnostic::admit_for_query(
            original,
            backend.maximum_sqlite_heap_bytes,
            None,
            METADATA.len().max(BODY.len()),
        )?;
        let scope_credit = SnapshotScope::prepare(original)?;
        Ok(Self {
            backend,
            original,
            active: None,
            phase: Phase::Dormant,
            pending_eof: false,
            eof_refused: false,
            diagnostic: Some(diagnostic),
            scope_credit: Some(scope_credit),
        })
    }

    fn check(
        &self,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        crate::content_store::checked_reader::check(self.original, boundary)?;
        busy::healthy(&self.backend.quarantined)
    }

    pub(crate) fn check_original(
        &self,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        crate::content_store::checked_reader::check(self.original, boundary)
    }

    fn resume(
        &mut self,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        if self.phase != Phase::Dormant {
            return Err(StoreError::Unsupported {
                capability: "comparison-snapshot-not-dormant",
            });
        }
        self.original
            .verify_live()
            .map_err(|error| crate::content_store::batch::admission_under(self.original, error))?;
        let mut check = || self.check(boundary);
        let staging = catalog::read_gate_with_boundary(&mut check)?;
        let connection = loop {
            check()?;
            match self
                .backend
                .read_connection
                .try_lock_for("lock-comparison-sqlite-snapshot")?
            {
                Some(connection) => break connection,
                None => std::thread::yield_now(),
            }
        };
        let credit = match self.scope_credit.take() {
            Some(credit) => credit,
            None => unreachable!("a clean dormant session retains its original scope credit"),
        };
        let (scope, begun) = SnapshotScope::begin(
            self.original,
            &connection,
            &self.backend.quarantined,
            boundary,
            Some(credit),
        )?;
        self.active = Some(ActiveSnapshot {
            scope,
            connection,
            staging,
        });
        self.phase = Phase::Active;
        if let Err(error) = begun {
            return self.close(boundary, Err(error));
        }
        Ok(())
    }

    pub(crate) fn record(
        &mut self,
        id: ContentId,
        maximum: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
        admit: impl FnOnce(u64) -> Result<(), StoreError>,
        consume: impl FnOnce(&[u8]) -> Result<bool, StoreError>,
    ) -> Result<bool, StoreError> {
        if self.phase == Phase::Dormant {
            self.resume(boundary)?;
        }
        if self.phase != Phase::Active {
            return Err(StoreError::Unsupported {
                capability: "comparison-snapshot-not-active",
            });
        }
        let active = match &self.active {
            Some(active) => active,
            None => unreachable!("an active comparison owns both native locks"),
        };
        let pending_eof = self.pending_eof;
        let mut first_query_edge = true;
        let mut check = || {
            let result = crate::content_store::checked_reader::check(self.original, boundary)
                .and_then(|()| busy::healthy(&self.backend.quarantined));
            if first_query_edge {
                first_query_edge = false;
                if pending_eof && result.is_err() {
                    self.eof_refused = true;
                }
            }
            result
        };
        // Exact encoded ID and query parameters are prepared by consume_record
        // before its first retry check. That check also discharges prior EOF;
        // the actual metadata query follows immediately without user work.
        let result = consume_record(
            RecordQuery {
                original: self.original,
                connection: &active.connection,
                quarantined: &self.backend.quarantined,
                id,
                maximum,
            },
            &mut check,
            AdmissionEdge::OriginalOnly,
            admit,
            consume,
        );
        self.pending_eof = result.is_ok();
        match result {
            Ok(valid) => Ok(valid),
            Err(error) => {
                self.close(boundary, Err(error))?;
                unreachable!("closing a failed record returns its owning failure")
            }
        }
    }

    pub(crate) fn pause(
        &mut self,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        if self.phase == Phase::Dormant {
            return Ok(());
        }
        if self.phase != Phase::Active {
            return Err(StoreError::Unsupported {
                capability: "comparison-snapshot-cannot-pause",
            });
        }
        let result = if self.pending_eof {
            let result = self.check(boundary);
            self.eof_refused |= result.is_err();
            self.pending_eof = false;
            result
        } else {
            Ok(())
        };
        self.close(boundary, result)
    }

    fn close(
        &mut self,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
        result: Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let active = match self.active.take() {
            Some(active) => active,
            None => unreachable!("native close consumes one active snapshot"),
        };
        let ActiveSnapshot {
            scope,
            connection,
            staging,
        } = active;
        let closed = scope.finish(
            self.original,
            &connection,
            boundary,
            &mut self.eof_refused,
            result,
        );
        // No native lock or borrowed body survives a successful pause or any
        // returned cleanup failure. Visitors are invoked only by the RAM driver.
        drop(connection);
        drop(staging);
        match closed {
            Ok(((), credit)) => {
                self.scope_credit = Some(credit);
                self.phase = Phase::Dormant;
                Ok(())
            }
            Err(error) => {
                self.phase = Phase::Failed;
                Err(error)
            }
        }
    }

    pub(crate) fn finish(
        mut self,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
        result: Result<(), StoreError>,
    ) -> (Result<(), StoreError>, bool) {
        let result = match result {
            Ok(()) => self.pause(boundary),
            Err(error) if self.phase == Phase::Active => {
                // Pure validation is pending: EOF and real cleanup still run
                // before the original failure can be exposed.
                match self.pause(boundary) {
                    Ok(()) => {
                        let credit = match self.scope_credit.take() {
                            Some(credit) => credit,
                            None => unreachable!("a clean pause retains its unused scope loan"),
                        };
                        Err(busy::snapshot::refuse_after_clean(credit, error))
                    }
                    Err(provider) => Err(provider),
                }
            }
            Err(error) => Err(error),
        };
        self.phase = Phase::Closed;
        let diagnostic = match self.diagnostic.take() {
            Some(diagnostic) => diagnostic,
            None => unreachable!("one session owns its original diagnostic loan"),
        };
        (
            diagnostic::retain_failure(diagnostic, || result),
            self.eof_refused,
        )
    }
}
