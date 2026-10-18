//! Closed pure traversal of privately parsed nodes with pending SQLite EOF.
//!
//! Only this access type receives those nodes. It discharges EOF and closes the
//! session before invoking a visitor; accounting is performed only after the
//! session's metadata edge has discharged the previous node's EOF.

use std::cell::Cell;

use super::*;
use crate::content_store::SqliteRamReadSession;
use crate::content_store::StoreError;

pub(in crate::ram) struct SqliteDifference<'drive, 'backend, 'original> {
    pub(in crate::ram) session: &'drive mut SqliteRamReadSession<'backend, 'original>,
    pub(in crate::ram) limits: super::super::RamStoreLimits,
    pub(in crate::ram) visits: &'drive mut u64,
    pub(in crate::ram) io_bytes: &'drive mut u64,
    pub(in crate::ram) boundary: &'drive mut dyn FnMut() -> Result<(), StoreError>,
    pub(in crate::ram) visitor: &'drive mut dyn FnMut(&str, u64) -> Result<(), RamStoreError>,
    pub(in crate::ram) pending_error: &'drive Cell<Option<RamStoreError>>,
}

pub(in crate::ram) fn validation_marker() -> StoreError {
    StoreError::Unsupported {
        capability: "bounded-canonical-validation-refused",
    }
}

impl DifferenceAccess for SqliteDifference<'_, '_, '_> {
    fn node(&mut self, expected: TreeRef) -> Result<TreeNode, RamStoreError> {
        if expected.id.schema_version() != 1 {
            return Err(RamStoreError::Invalid("RAM storage schema"));
        }
        self.reject_exhausted_visit()?;
        let node = Cell::new(None);
        let first = self.pending_error;
        let valid = self.session.record(
            expected.id,
            4096,
            self.boundary,
            |length| {
                let result = (|| {
                    if length > 4096 {
                        return Err(RamStoreError::Limit("single canonical object"));
                    }
                    *self.visits = self
                        .visits
                        .checked_add(1)
                        .ok_or(RamStoreError::Limit("object visits"))?;
                    *self.io_bytes = self
                        .io_bytes
                        .checked_add(length)
                        .ok_or(RamStoreError::Limit("I/O bytes"))?;
                    if *self.visits > self.limits.maximum_object_visits {
                        return Err(RamStoreError::Limit("object visits"));
                    }
                    if *self.io_bytes > self.limits.maximum_io_bytes {
                        return Err(RamStoreError::Limit("I/O bytes"));
                    }
                    Ok(())
                })();
                result.map_err(|error| {
                    first.set(Some(error));
                    validation_marker()
                })
            },
            |bytes| {
                Ok(
                    match super::super::canonical_tree::read_tree_canonical(bytes, expected) {
                        Ok(value) => {
                            node.set(Some(value));
                            true
                        }
                        Err(error) => {
                            first.set(Some(error));
                            false
                        }
                    },
                )
            },
        )?;
        if !valid {
            return Err(validation_marker().into());
        }
        match node.take() {
            Some(node) => Ok(node),
            None => unreachable!("successful closed canonical validation retains its node"),
        }
    }

    fn changed(&mut self, region: &str, page: u64) -> Result<(), RamStoreError> {
        self.session.pause(self.boundary)?;
        // Both native locks are gone and this node's EOF succeeded. A visitor
        // never consumes private pending bytes or runs inside the SQL snapshot.
        (self.visitor)(region, page)
    }
}

impl SqliteDifference<'_, '_, '_> {
    fn reject_exhausted_visit(&mut self) -> Result<(), RamStoreError> {
        let (visits, limit) = match self.visits.checked_add(1) {
            None => (*self.visits, "object visits"),
            Some(visits) if *self.io_bytes == u64::MAX => (visits, "I/O bytes"),
            Some(visits) if visits > self.limits.maximum_object_visits => (visits, "object visits"),
            Some(visits) if *self.io_bytes >= self.limits.maximum_io_bytes => (visits, "I/O bytes"),
            Some(_) => return Ok(()),
        };

        // A guaranteed refusal reads no metadata. Pending EOF and cleanup
        // precede the same two refusal polls and attempted-visit accounting.
        self.session.pause(self.boundary)?;
        self.session.check_original(self.boundary)?;
        self.session.check_original(self.boundary)?;
        *self.visits = visits;
        Err(RamStoreError::Limit(limit))
    }
}
