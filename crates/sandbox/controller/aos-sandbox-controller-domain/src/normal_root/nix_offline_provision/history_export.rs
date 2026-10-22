//! Genuine read-only startup custody for offline journal DATA export.
//!
//! This V7 purpose retains only the public base credentials. It has no approval
//! proposal, private candidate, hierarchy authorization or hardware loan. An
//! export can describe an interrupted job without reopening that job's owner.

use super::{
    Error, OfflineNixPrepareStartupErrorV3, OfflineNixPrepareStartupV3, OfflinePrepareModeV3,
};

/// Retains one exact V7 history-export launch and its original observations.
pub struct OfflineNixHistoryExportStartupV7 {
    original: OfflineNixPrepareStartupV3,
}

impl OfflineNixHistoryExportStartupV7 {
    /// Creates empty custody without opening protected state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            original: OfflineNixPrepareStartupV3::new(),
        }
    }

    /// Captures the selected immutable V7 unit and public delivery originals.
    ///
    /// # Errors
    /// Retains actual image, process, manager or credential failures. Repeated
    /// and interrupted capture stay fenced; no hardware owner is recovered.
    pub fn capture_and_admit(&mut self) -> Result<(), &OfflineNixPrepareStartupErrorV3> {
        self.original
            .capture_mode(OfflinePrepareModeV3::ExportHistoryV7)
    }

    /// Lends the genuine admitted V7 launch after a fresh complete recheck.
    ///
    /// # Errors
    /// Rejects absent, wrong-purpose, interrupted, failed or changed custody.
    pub fn borrow_original(
        &mut self,
    ) -> Result<OfflineNixHistoryExportOriginV7<'_>, &OfflineNixPrepareStartupErrorV3> {
        if self
            .original
            .recheck_mode(OfflinePrepareModeV3::ExportHistoryV7)
            .is_err()
        {
            return Err(self.original.failure.get_or_insert(Error::Fenced));
        }

        Ok(OfflineNixHistoryExportOriginV7 {
            original: &mut self.original,
        })
    }

    /// Borrows the retained first startup failure without releasing custody.
    pub fn failure(&self) -> Option<&OfflineNixPrepareStartupErrorV3> {
        self.original.failure()
    }
}

impl Default for OfflineNixHistoryExportStartupV7 {
    fn default() -> Self {
        Self::new()
    }
}

/// Lends actual V7 startup custody exclusively to its fixed read-only owner.
///
/// This loan has no public constructor, clone, raw descriptor or conversion to
/// an approval-delivery or hardware origin. Returned public bytes remain DATA.
pub struct OfflineNixHistoryExportOriginV7<'startup> {
    original: &'startup mut OfflineNixPrepareStartupV3,
}

impl OfflineNixHistoryExportOriginV7<'_> {
    /// Rechecks the same immutable launch and original public credentials.
    ///
    /// # Errors
    /// Retains actual observation failures and fences changed or failed custody.
    pub fn recheck(&mut self) -> Result<(), &OfflineNixPrepareStartupErrorV3> {
        self.original
            .recheck_mode(OfflinePrepareModeV3::ExportHistoryV7)
    }

    /// Borrows the original public node and independent approval key.
    ///
    /// # Errors
    /// Rejects a fenced, wrong-purpose or missing credential original.
    pub fn public_originals(&self) -> Result<(&[u8; 16], &[u8; 48]), Error> {
        if !self.original.usable
            || self.original.mode != Some(OfflinePrepareModeV3::ExportHistoryV7)
        {
            return Err(Error::Fenced);
        }
        let (node, approval) = self.original.credentials.public_originals()?;

        Ok((
            node.try_into().map_err(|_| Error::Rejected)?,
            approval.try_into().map_err(|_| Error::Rejected)?,
        ))
    }

    /// Borrows the retained original startup cause without releasing custody.
    pub fn failure(&self) -> Option<&OfflineNixPrepareStartupErrorV3> {
        self.original.failure()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_export_cannot_borrow_empty_wrong_or_interrupted_startup() {
        for mode in [
            None,
            Some(OfflinePrepareModeV3::PrepareKeys),
            Some(OfflinePrepareModeV3::ExportHistoryV7),
        ] {
            let mut startup = OfflineNixHistoryExportStartupV7::new();
            startup.original.mode = mode;
            startup.original.attempted = mode.is_some();

            assert!(startup.borrow_original().is_err());
            assert!(startup.failure().is_some());
        }
    }
}
